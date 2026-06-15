import hashlib
import mimetypes
import os
import re
import secrets
from functools import wraps
from urllib.parse import urlencode

import bleach
import markdown
from PIL import Image, UnidentifiedImageError
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_login import current_user, login_user, logout_user
from sqlalchemy import event, or_, select
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config
from extensions import db, login_manager
from models import Book, Cover, Genre, Review, Role, User

ADMIN = "администратор"
MODER = "модератор"
USER = "пользователь"

IMAGE_EXTENSIONS = {
    "JPEG": ".jpg",
    "PNG": ".png",
    "GIF": ".gif",
    "WEBP": ".webp",
    "BMP": ".bmp",
}

SEED_COVERS_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static", "seed_covers")

SEED_COVER_FILES = {
    "Евгений Онегин": "евг онег.webp",
    "Капитанская дочка": "капитанская дочка.webp",
    "Герой нашего времени": "герой нашего времени.jpg",
    "Мёртвые души": "мертвые души.webp",
    "Ревизор": "ревизор.webp",
    "Отцы и дети": "отцы.webp",
    "Преступление и наказание": "преступление.jpg",
    "Война и мир": "война.webp",
    "Анна Каренина": "анна.webp",
    "Вишнёвый сад": "вишневый сад.jpg",
    "На дне": "на дне.webp",
    "Мастер и Маргарита": "мастер и марг.webp",
    "Тихий Дон": "тихий дон.webp",
    "Судьба человека": "судьба человека.png",
    "А зори здесь тихие": "а зори здесь тихие.webp",
    "Недоросль": "недоросль.webp",
    "Горе от ума": "горе от ума.png",
    "Обломов": "обломов.jpg",
    "Гроза": "гроза.webp",
    "Слово о полку Игореве": "слово.jpg",
    "Ромео и Джульетта": "ромео.jpg",
    "Маленький принц": "маленький принц.jpg",
}

AUTH_MSG = "Для выполнения данного действия необходимо пройти процедуру аутентификации"
RIGHTS_MSG = "У вас недостаточно прав для выполнения данного действия"
SAVE_ERR = "При сохранении данных возникла ошибка. Проверьте корректность введённых данных."
LOGIN_ERR = "Невозможно аутентифицироваться с указанными логином и паролем"

ALLOWED_MD_TAGS = [
    "p", "br", "strong", "em", "b", "i", "ul", "ol", "li", "blockquote",
    "code", "pre", "a", "h1", "h2", "h3", "h4", "hr", "table", "thead",
    "tbody", "tr", "th", "td",
]
ALLOWED_MD_ATTRS = {"a": ["href", "title", "target", "rel"]}


@event.listens_for(Engine, "connect")
def enable_sqlite_fk(dbapi_conn, conn_record):
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    finally:
        cursor.close()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def need_login():
        flash(AUTH_MSG, "warning")
        return redirect(url_for("login", next=request.url))

    @app.template_filter("markdown")
    def markdown_filter(text):
        return md_to_html(text)

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("_csrf_token")
            form_token = request.form.get("_csrf_token")
            if not token or token != form_token:
                abort(400)

    @app.template_global()
    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return session["_csrf_token"]

    @app.template_global()
    def has_role(*roles):
        return current_user.is_authenticated and current_user.role_name in roles

    @app.template_global()
    def page_url(page):
        args = request.args.to_dict(flat=False)
        args["page"] = [str(page)]
        return request.path + "?" + urlencode(args, doseq=True)

    @app.route("/")
    def index():
        page = request.args.get("page", 1, type=int)
        filters = read_filters()

        stmt = select(Book)
        if filters["title"]:
            stmt = stmt.where(text_match(Book.title, filters["title"]))
        if filters["author"]:
            stmt = stmt.where(text_match(Book.author, filters["author"]))
        if filters["genre_ids"]:
            stmt = stmt.where(Book.genres.any(Genre.id.in_(filters["genre_ids"])))
        if filters["years"]:
            stmt = stmt.where(Book.year.in_(filters["years"]))
        if filters["pages_min"] is not None:
            stmt = stmt.where(Book.pages >= filters["pages_min"])
        if filters["pages_max"] is not None:
            stmt = stmt.where(Book.pages <= filters["pages_max"])

        stmt = stmt.order_by(Book.year.desc(), Book.id.desc())
        pages = db.paginate(stmt, page=page, per_page=10, error_out=False)

        all_genres = Genre.query.order_by(Genre.name).all()
        years_stmt = select(Book.year).distinct().order_by(Book.year.desc())
        all_years = [row[0] for row in db.session.execute(years_stmt).all()]

        return render_template(
            "index.html",
            books=pages.items,
            pages=pages,
            all_genres=all_genres,
            all_years=all_years,
            filters=filters,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            login_value = request.form.get("login", "").strip()
            password = request.form.get("password", "")
            remember = bool(request.form.get("remember"))
            user = User.query.filter_by(login=login_value).first()

            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=remember)
                next_url = request.args.get("next")
                return redirect(next_url or url_for("index"))

            flash(LOGIN_ERR, "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(request.referrer or url_for("index"))

    @app.route("/books/new", methods=["GET", "POST"])
    @role_required(ADMIN)
    def add_book():
        genres = Genre.query.order_by(Genre.name).all()

        if request.method == "POST":
            form = request.form
            selected = ids_from_form("genres")
            cover_file = request.files.get("cover")
            saved_path = None

            try:
                data = book_data_from_form(form)
                if not selected:
                    raise ValueError("У книги должен быть хотя бы один жанр")
                if not cover_file or not cover_file.filename:
                    raise ValueError("Обложка обязательна")
                if not is_image(cover_file):
                    raise ValueError("Обложка должна быть изображением")

                selected_genres = Genre.query.filter(Genre.id.in_(selected)).all()
                if not selected_genres:
                    raise ValueError("У книги должен быть хотя бы один существующий жанр")

                book = Book(**data)
                book.genres = selected_genres
                db.session.add(book)
                db.session.flush()

                saved_path = add_cover(cover_file, book.id)
                db.session.commit()
                flash("Книга успешно добавлена", "success")
                return redirect(url_for("show_book", book_id=book.id))
            except Exception:
                db.session.rollback()
                remove_file(saved_path)
                flash(SAVE_ERR, "danger")
                return render_template(
                    "book_form.html",
                    title="Добавление книги",
                    book=None,
                    genres=genres,
                    selected=selected,
                    action=url_for("add_book"),
                    is_edit=False,
                    form=form,
                )

        return render_template(
            "book_form.html",
            title="Добавление книги",
            book=None,
            genres=genres,
            selected=[],
            action=url_for("add_book"),
            is_edit=False,
            form={},
        )

    @app.route("/books/<int:book_id>/edit", methods=["GET", "POST"])
    @role_required(ADMIN, MODER)
    def edit_book(book_id):
        book = db.get_or_404(Book, book_id)
        genres = Genre.query.order_by(Genre.name).all()

        if request.method == "POST":
            form = request.form
            selected = ids_from_form("genres")

            try:
                data = book_data_from_form(form)
                if not selected:
                    raise ValueError("У книги должен быть хотя бы один жанр")

                selected_genres = Genre.query.filter(Genre.id.in_(selected)).all()
                if not selected_genres:
                    raise ValueError("У книги должен быть хотя бы один существующий жанр")

                for key, value in data.items():
                    setattr(book, key, value)
                book.genres = selected_genres
                db.session.commit()
                flash("Данные книги успешно обновлены", "success")
                return redirect(url_for("show_book", book_id=book.id))
            except Exception:
                db.session.rollback()
                flash(SAVE_ERR, "danger")
                return render_template(
                    "book_form.html",
                    title="Редактирование книги",
                    book=book,
                    genres=genres,
                    selected=selected,
                    action=url_for("edit_book", book_id=book.id),
                    is_edit=True,
                    form=form,
                )

        selected = [genre.id for genre in book.genres]
        return render_template(
            "book_form.html",
            title="Редактирование книги",
            book=book,
            genres=genres,
            selected=selected,
            action=url_for("edit_book", book_id=book.id),
            is_edit=True,
            form={},
        )

    @app.route("/books/<int:book_id>/delete", methods=["POST"])
    @role_required(ADMIN)
    def delete_book(book_id):
        book = db.get_or_404(Book, book_id)
        filename = book.cover.filename if book.cover else None
        db.session.delete(book)
        db.session.commit()

        if filename and Cover.query.filter_by(filename=filename).count() == 0:
            remove_file(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        flash("Книга успешно удалена", "success")
        return redirect(url_for("index"))

    @app.route("/books/<int:book_id>")
    def show_book(book_id):
        book = db.get_or_404(Book, book_id)
        own_review = None
        can_review = False
        reviews = sorted(book.reviews, key=lambda item: item.created_at, reverse=True)

        if current_user.is_authenticated:
            own_review = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
            can_review = current_user.role_name in (ADMIN, MODER, USER) and own_review is None
            if own_review:
                reviews = [review for review in reviews if review.id != own_review.id]

        return render_template(
            "book_view.html",
            book=book,
            own_review=own_review,
            can_review=can_review,
            reviews=reviews,
        )

    @app.route("/books/<int:book_id>/review", methods=["GET", "POST"])
    @role_required(ADMIN, MODER, USER)
    def add_review(book_id):
        book = db.get_or_404(Book, book_id)
        old_review = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
        if old_review:
            flash("Вы уже оставляли рецензию на эту книгу", "info")
            return redirect(url_for("show_book", book_id=book.id))

        if request.method == "POST":
            try:
                rating = int(request.form.get("rating", 5))
                text = clean_markdown(request.form.get("text", ""))
                if rating not in range(0, 6) or not text:
                    raise ValueError("Некорректные данные рецензии")

                review = Review(book_id=book.id, user_id=current_user.id, rating=rating, text=text)
                db.session.add(review)
                db.session.commit()
                flash("Рецензия успешно добавлена", "success")
                return redirect(url_for("show_book", book_id=book.id))
            except Exception:
                db.session.rollback()
                flash("При сохранении рецензии возникла ошибка", "danger")

        return render_template("review_form.html", book=book)

    @app.route("/covers/<path:filename>")
    def cover_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.cli.command("init-db")
    def init_db():
        db.drop_all()
        db.create_all()
        seed_db()
        print("База данных создана и заполнена тестовыми данными.")

    return app


def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash(AUTH_MSG, "warning")
                return redirect(url_for("login", next=request.url))
            if current_user.role_name not in roles:
                flash(RIGHTS_MSG, "danger")
                return redirect(url_for("index"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def text_match(column, value):
    """Partial text search for title/author filters.

    SQLAlchemy's ilike is the clearest way to express a case-insensitive
    partial match. The extra case variants keep local SQLite demos with
    Cyrillic text usable, because SQLite's lower()/upper() functions do not
    reliably normalize non-Latin characters.
    """
    terms = {value, value.lower(), value.upper(), value.capitalize(), value.title()}
    return or_(*[column.ilike(f"%{term}%") for term in terms if term])


def read_filters():
    return {
        "title": request.args.get("title", "").strip(),
        "author": request.args.get("author", "").strip(),
        "genre_ids": ids_from_args("genres"),
        "years": ids_from_args("years"),
        "pages_min": int_or_none(request.args.get("pages_min")),
        "pages_max": int_or_none(request.args.get("pages_max")),
    }


def ids_from_args(name):
    ids = []
    for value in request.args.getlist(name):
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    return ids


def ids_from_form(name):
    ids = []
    for value in request.form.getlist(name):
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    return ids


def int_or_none(value):
    try:
        if value in (None, ""):
            return None
        return int(value)
    except ValueError:
        return None


def book_data_from_form(form):
    title = form.get("title", "").strip()
    description = clean_markdown(form.get("description", ""))
    year = int(form.get("year", ""))
    publisher = form.get("publisher", "").strip()
    author = form.get("author", "").strip()
    pages = int(form.get("pages", ""))

    if not all([title, description, year, publisher, author, pages]):
        raise ValueError("Заполнены не все обязательные поля")
    if year < 1 or pages < 1:
        raise ValueError("Год и объём должны быть положительными")

    return {
        "title": title,
        "description": description,
        "year": year,
        "publisher": publisher,
        "author": author,
        "pages": pages,
    }


def normalize_markdown(text):
    text = text or ""
    text = re.sub(r"^(\s*[-*+]\s*)\[[ xX]\]\s+", r"\1", text, flags=re.MULTILINE)

    return text


def clean_markdown(text):
    text = normalize_markdown(text)
    return bleach.clean(text, tags=[], attributes={}, strip=True).strip()


def md_to_html(text):
    text = normalize_markdown(text)
    raw_html = markdown.markdown(text, extensions=["extra", "nl2br"])
    clean_html = bleach.clean(raw_html, tags=ALLOWED_MD_TAGS, attributes=ALLOWED_MD_ATTRS, strip=True)
    return bleach.linkify(clean_html)

def is_image(file):
    """Validate that an uploaded cover is a real image, not only image/* by MIME.

    Browser-provided MIME type and extension can be spoofed, so the file is
    opened and verified with Pillow. After validation the stream is rewound,
    because the same FileStorage object is read later in add_cover().
    """
    try:
        file.stream.seek(0)
        image = Image.open(file.stream)
        image_format = image.format
        image.verify()
        file._validated_image_format = image_format
        file._validated_mime_type = Image.MIME.get(image_format, file.mimetype or "image/octet-stream")
        file.stream.seek(0)
        return image_format is not None
    except (UnidentifiedImageError, OSError, ValueError):
        file.stream.seek(0)
        return False


def add_cover(file, book_id):
    data = file.read()
    file.seek(0)
    md5_hash = hashlib.md5(data).hexdigest()
    old_cover = Cover.query.filter_by(md5_hash=md5_hash).first()

    if old_cover:
        cover = Cover(
            filename=old_cover.filename,
            mime_type=old_cover.mime_type,
            md5_hash=old_cover.md5_hash,
            book_id=book_id,
        )
        db.session.add(cover)
        return None

    image_format = getattr(file, "_validated_image_format", None)
    mime_type = getattr(file, "_validated_mime_type", None) or file.mimetype or "application/octet-stream"
    ext = file_ext(mime_type, image_format)
    cover = Cover(filename="pending", mime_type=mime_type, md5_hash=md5_hash, book_id=book_id)
    db.session.add(cover)
    db.session.flush()

    cover.filename = f"{cover.id}{ext}"
    path = os.path.join(Config.UPLOAD_FOLDER, cover.filename)
    with open(path, "wb") as out:
        out.write(data)
    return path


def file_ext(mime_type, image_format=None):
    if image_format in IMAGE_EXTENSIONS:
        return IMAGE_EXTENSIONS[image_format]
    return mimetypes.guess_extension(mime_type) or ".img"


def remove_file(path):
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass



def make_seed_cover(book, idx):
    source_name = SEED_COVER_FILES.get(book.title)

    if source_name:
        source_path = os.path.join(SEED_COVERS_FOLDER, source_name)

        if os.path.exists(source_path):
            try:
                with Image.open(source_path) as image:
                    image_format = image.format
                    image.verify()

                with open(source_path, "rb") as inp:
                    data = inp.read()

                md5_hash = hashlib.md5(data).hexdigest()
                mime_type = Image.MIME.get(
                    image_format,
                    mimetypes.guess_type(source_path)[0] or "image/octet-stream",
                )
                ext = file_ext(mime_type, image_format)
                filename = f"seed_{idx}{ext}"
                path = os.path.join(Config.UPLOAD_FOLDER, filename)

                with open(path, "wb") as out:
                    out.write(data)

                cover = Cover(
                    filename=filename,
                    mime_type=mime_type,
                    md5_hash=md5_hash,
                    book_id=book.id,
                )
                db.session.add(cover)
                return
            except (UnidentifiedImageError, OSError, ValueError):
                pass

    colors = ["#f9c5d1", "#f7a9bd", "#fbd6df", "#f4b6c2", "#ffdce6"]
    color = colors[idx % len(colors)]
    safe_title = bleach.clean(book.title, tags=[], strip=True)
    safe_author = bleach.clean(book.author, tags=[], strip=True)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="420" height="620" viewBox="0 0 420 620">
  <rect width="420" height="620" rx="28" fill="{color}"/>
  <rect x="28" y="28" width="364" height="564" rx="22" fill="#fff7fa" opacity="0.88"/>
  <text x="210" y="210" text-anchor="middle" font-family="Arial, sans-serif" font-size="34" font-weight="700" fill="#8f3f5b">Школьная</text>
  <text x="210" y="255" text-anchor="middle" font-family="Arial, sans-serif" font-size="34" font-weight="700" fill="#8f3f5b">библиотека</text>
  <text x="210" y="350" text-anchor="middle" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#5f2b3a">{safe_title}</text>
  <text x="210" y="395" text-anchor="middle" font-family="Arial, sans-serif" font-size="20" fill="#7a4d5b">{safe_author}</text>
</svg>"""
    data = svg.encode("utf-8")
    md5_hash = hashlib.md5(data).hexdigest()
    filename = f"seed_{idx}.svg"
    path = os.path.join(Config.UPLOAD_FOLDER, filename)
    with open(path, "wb") as out:
        out.write(data)
    cover = Cover(filename=filename, mime_type="image/svg+xml", md5_hash=md5_hash, book_id=book.id)
    db.session.add(cover)


def seed_db():
    roles = [
        Role(name=ADMIN, description="Суперпользователь, имеет полный доступ к системе."),
        Role(name=MODER, description="Может редактировать книги и модерировать рецензии."),
        Role(name=USER, description="Может оставлять рецензии."),
    ]
    db.session.add_all(roles)
    db.session.flush()

    genre_names = [
        "Роман", "Повесть", "Рассказ", "Комедия", "Драма", "Трагедия",
        "Поэма", "Поэзия", "Фантастика", "Приключения", "Сатира",
        "История", "Учебная литература",
    ]
    genres = {name: Genre(name=name) for name in genre_names}
    db.session.add_all(genres.values())
    db.session.flush()

    users = [
        User(
            login="admin",
            password_hash=generate_password_hash("admin123"),
            last_name="Админов",
            first_name="Админ",
            middle_name="Админович",
            role_id=roles[0].id,
        ),
        User(
            login="moderator",
            password_hash=generate_password_hash("moder123"),
            last_name="Тихонкова",
            first_name="Анастасия",
            middle_name="Александровна",
            role_id=roles[1].id,
        ),
        User(
            login="user",
            password_hash=generate_password_hash("user123"),
            last_name="Никитин",
            first_name="Никита",
            middle_name="Никитьевич",
            role_id=roles[2].id,
        ),
    ]
    db.session.add_all(users)

    books = [
        ("Евгений Онегин", "Роман в стихах о взрослении, любви, выборе и светском обществе XIX века.", 1833, "Азбука", "Александр Пушкин", 224, ["Роман", "Поэзия"]),
        ("Капитанская дочка", "Историческая повесть о чести, долге и событиях пугачёвского восстания.", 1836, "Эксмо", "Александр Пушкин", 192, ["Повесть", "История"]),
        ("Герой нашего времени", "Психологический роман о Печорине и противоречиях человека своего времени.", 1840, "Азбука", "Михаил Лермонтов", 256, ["Роман"]),
        ("Мёртвые души", "Сатирическая поэма о Чичикове и помещичьей России.", 1842, "АСТ", "Николай Гоголь", 352, ["Поэма", "Сатира"]),
        ("Ревизор", "Комедия о чиновниках уездного города и страхе перед проверкой.", 1836, "АСТ", "Николай Гоголь", 128, ["Комедия", "Сатира"]),
        ("Отцы и дети", "Роман о конфликте поколений, нигилизме и поиске жизненной позиции.", 1862, "Эксмо", "Иван Тургенев", 288, ["Роман"]),
        ("Преступление и наказание", "Роман о преступлении, совести, раскаянии и нравственном выборе.", 1866, "Азбука", "Фёдор Достоевский", 608, ["Роман"]),
        ("Война и мир", "Эпопея о судьбах людей на фоне Отечественной войны 1812 года.", 1869, "Эксмо", "Лев Толстой", 1225, ["Роман", "История"]),
        ("Анна Каренина", "Роман о семье, любви, обществе и личной ответственности.", 1877, "Азбука", "Лев Толстой", 864, ["Роман"]),
        ("Вишнёвый сад", "Пьеса о расставании со старым миром и неизбежности перемен.", 1904, "АСТ", "Антон Чехов", 96, ["Драма"]),
        ("На дне", "Драма о людях ночлежки, надежде, правде и сострадании.", 1902, "Эксмо", "Максим Горький", 160, ["Драма"]),
        ("Мастер и Маргарита", "Роман о любви, творчестве, свободе и ответственности человека.", 1967, "Азбука", "Михаил Булгаков", 512, ["Роман", "Фантастика"]),
        ("Тихий Дон", "Роман-эпопея о судьбе казачества в годы войны и революции.", 1940, "АСТ", "Михаил Шолохов", 992, ["Роман", "История"]),
        ("Судьба человека", "Рассказ о стойкости, потере и человеческом достоинстве после войны.", 1956, "Детская литература", "Михаил Шолохов", 64, ["Рассказ"]),
        ("А зори здесь тихие", "Повесть о мужестве девушек-зенитчиц во время Великой Отечественной войны.", 1969, "Детская литература", "Борис Васильев", 224, ["Повесть", "История"]),
        ("Недоросль", "Комедия о невежестве, воспитании и нравственных пороках дворянства.", 1782, "АСТ", "Денис Фонвизин", 112, ["Комедия", "Сатира"]),
        ("Горе от ума", "Комедия о столкновении свободомыслия Чацкого с фамусовским обществом.", 1825, "Азбука", "Александр Грибоедов", 160, ["Комедия"]),
        ("Обломов", "Роман о характере, бездействии, мечтах и столкновении разных жизненных укладов.", 1859, "Эксмо", "Иван Гончаров", 544, ["Роман"]),
        ("Гроза", "Драма о свободе личности, семейном давлении и конфликте с тёмным царством.", 1859, "АСТ", "Александр Островский", 128, ["Драма"]),
        ("Слово о полку Игореве", "Памятник древнерусской литературы о походе князя Игоря и судьбе Русской земли.", 1185, "Просвещение", "Неизвестный автор", 96, ["Поэма", "История"]),
        ("Ромео и Джульетта", "Трагедия о любви, вражде семей и цене непримиримости.", 1597, "Азбука", "Уильям Шекспир", 192, ["Трагедия", "Драма"]),
        ("Маленький принц", "Философская сказка о дружбе, ответственности и взрослении.", 1943, "Эксмо", "Антуан де Сент-Экзюпери", 112, ["Повесть", "Фантастика"]),
    ]
    for idx, (title, desc, year, publisher, author, pages, book_genres) in enumerate(books, start=1):
        book = Book(
            title=title,
            description=clean_markdown(desc),
            year=year,
            publisher=publisher,
            author=author,
            pages=pages,
            genres=[genres[name] for name in book_genres],
        )
        db.session.add(book)
        db.session.flush()
        make_seed_cover(book, idx)

    db.session.commit()


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
