from flask_login import UserMixin
from sqlalchemy import CheckConstraint, UniqueConstraint, func
from sqlalchemy.dialects import mysql

from extensions import db


book_genres = db.Table(
    "book_genres",
    db.Column("book_id", db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), primary_key=True),
    db.Column("genre_id", db.Integer, db.ForeignKey("genres.id", ondelete="CASCADE"), primary_key=True),
)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)

    users = db.relationship("User", back_populates="role")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    middle_name = db.Column(db.String(80), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)

    role = db.relationship("Role", back_populates="users")
    reviews = db.relationship("Review", back_populates="user", cascade="all, delete-orphan")

    @property
    def full_name(self):
        parts = [self.last_name, self.first_name, self.middle_name]
        return " ".join(part for part in parts if part)

    @property
    def role_name(self):
        return self.role.name if self.role else ""


class Genre(db.Model):
    __tablename__ = "genres"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)

    books = db.relationship("Book", secondary=book_genres, back_populates="genres")


class Book(db.Model):
    __tablename__ = "books"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    year = db.Column(db.Integer().with_variant(mysql.YEAR, "mysql"), nullable=False)
    publisher = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    pages = db.Column(db.Integer, nullable=False)

    genres = db.relationship("Genre", secondary=book_genres, back_populates="books")
    cover = db.relationship("Cover", back_populates="book", cascade="all, delete-orphan", uselist=False)
    reviews = db.relationship("Review", back_populates="book", cascade="all, delete-orphan")

    @property
    def review_count(self):
        return len(self.reviews)

    @property
    def avg_rating(self):
        if not self.reviews:
            return None
        return round(sum(review.rating for review in self.reviews) / len(self.reviews), 1)


class Cover(db.Model):
    __tablename__ = "covers"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False, unique=True)

    book = db.relationship("Book", back_populates="cover")


class Review(db.Model):
    __tablename__ = "reviews"
    __table_args__ = (
        UniqueConstraint("book_id", "user_id", name="uq_review_book_user"),
        CheckConstraint("rating BETWEEN 0 AND 5", name="ck_review_rating_range"),
    )

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())

    book = db.relationship("Book", back_populates="reviews")
    user = db.relationship("User", back_populates="reviews")
