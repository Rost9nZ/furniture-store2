from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from psycopg2 import connect, sql
from config import db_config, SECRET_KEY
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import json
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'ku.markus@mail.ru'
app.config['MAIL_PASSWORD'] = 'JKrBGDtvSp0HRvvVYpM4'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

login_manager = LoginManager(app)
login_manager.login_view = "login"

def create_connection():
    """Создает подключение к базе данных."""
    try:
        return connect(**db_config)
    except Exception as e:
        print("Ошибка подключения к БД:", e)
        return None

class User(UserMixin):
    """Модель пользователя для Flask-Login."""
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    """Загружает пользователя по ID."""
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Обработчик входа в систему."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
                user_data = cursor.fetchone()

                if user_data and check_password_hash(user_data[1], password):
                    login_user(User(user_data[0]))
                    flash('Успешная авторизация!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Неверные учетные данные.', 'danger')

            except Exception as e:
                flash(f"Ошибка авторизации: {e}", 'danger')

            finally:
                cursor.close()
                connection.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Обработчик регистрации пользователей."""
    if request.method == 'POST':
        new_username = request.form['new_username']
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Пароли не совпадают.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(new_password)

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (new_username, email))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash('Пользователь с таким именем или email уже существует.', 'warning')
                else:
                    cursor.execute("""
                        INSERT INTO users (username, email, password_hash)
                        VALUES (%s, %s, %s)
                    """, (new_username, email, hashed_password))
                    connection.commit()
                    flash('Регистрация успешна! Теперь вы можете войти.', 'success')
                    return redirect(url_for('login'))

            except Exception as e:
                flash(f"Ошибка регистрации: {e}", 'danger')

            finally:
                cursor.close()
                connection.close()

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Обработчик для выхода пользователя."""
    logout_user()
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('login'))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/avatars'  # Папка для аватарок

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    connection = create_connection()
    if not connection:
        flash("Ошибка подключения к базе данных", "danger")
        return redirect(url_for('index'))

    cursor = connection.cursor()

    # Загрузить текущие данные пользователя
    cursor.execute("SELECT username, email, avatar FROM users WHERE id = %s", (current_user.id,))
    result = cursor.fetchone()
    if not result:
        flash("Пользователь не найден", "danger")
        cursor.close()
        connection.close()
        return redirect(url_for('index'))

    db_username, db_email, db_avatar = result

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()

        if username != db_username:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash("Пользователь с таким логином уже существует", "danger")
                cursor.close()
                connection.close()
                return redirect(url_for('profile'))

        try:
            cursor.execute("UPDATE users SET username=%s, email=%s WHERE id=%s", (username, email, current_user.id))
            connection.commit()

            if 'avatar' in request.files:
                file = request.files['avatar']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    relative_path = os.path.join('avatars', filename).replace('\\', '/')
                    absolute_path = os.path.join('static', relative_path)

                    if db_avatar:
                        old_path = os.path.join('static', db_avatar.replace('\\', '/'))
                        if os.path.exists(old_path) and 'default-avatar' not in db_avatar:
                            try:
                                os.remove(old_path)
                            except Exception as e:
                                print(f"Не удалось удалить старую аватарку: {e}")

                    file.save(absolute_path)
                    cursor.execute("UPDATE users SET avatar=%s WHERE id=%s", (relative_path, current_user.id))
                    connection.commit()
            flash('Профиль обновлен', 'success')

        except Exception as e:
            connection.rollback()
            flash(f"Ошибка при обновлении профиля: {e}", "danger")

        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('profile'))

    # Для GET-запроса
    user_data = {
        'username': db_username,
        'email': db_email,
        'avatar': db_avatar
    }

    # Загрузка заказов
    try:
        cursor.execute("""
            SELECT id, last_name, first_name, middle_name, phone, email,
                   delivery, delivery_price, total_price, created_at, is_paid
            FROM orders WHERE user_id = %s ORDER BY created_at DESC
        """, (current_user.id,))
        orders_result = cursor.fetchall()

        orders = []
        for order_row in orders_result:
            order = {
                'id': order_row[0],
                'last_name': order_row[1],
                'first_name': order_row[2],
                'middle_name': order_row[3],
                'phone': order_row[4],
                'email': order_row[5],
                'delivery': order_row[6],
                'delivery_price': order_row[7],
                'total_price': order_row[8],
                'created_at': order_row[9],
                'is_paid': order_row[10],
                'items': []
            }

            cursor.execute("""
                SELECT product_type, product_id, name, description, price, quantity
                FROM order_items WHERE order_id = %s
            """, (order['id'],))
            items_result = cursor.fetchall()

            for item_row in items_result:
                order['items'].append({
                    'product_type': item_row[0],
                    'product_id': item_row[1],
                    'name': item_row[2],
                    'description': item_row[3],
                    'price': item_row[4],
                    'quantity': item_row[5],
                })
            orders.append(order)

    except Exception as e:
        flash(f"Ошибка при загрузке заказов: {e}", "danger")
        orders = []

    finally:
        cursor.close()
        connection.close()

    return render_template('profile.html', user=user_data, orders=orders)

@app.route('/')
def index():
    """Главная страница с товарами."""
    connection = create_connection()
    tables = []
    chairs = []

    if connection:
        try:
            cursor = connection.cursor()

            # Получаем столы
            cursor.execute("SELECT id, name, price, image, quantity, description, size, leg_color, material_type FROM tables")
            tables = [
                {
                    "id": row[0],
                    "name": row[1],
                    "price": row[2],
                    "image": row[3],
                    "quantity": row[4],
                    "description": row[5],
                    "size": row[6],
                    "leg_color": row[7],
                    "material_type": row[8]
                }
                for row in cursor.fetchall()
            ]

            # Получаем стулья
            cursor.execute("SELECT id, name, description, price, image, leg_color, quantity, is_rotating FROM chairs")
            chairs = [
                {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "price": row[3],
                    "image": row[4],
                    "leg_color": row[5],
                    "quantity": row[6],
                    "is_rotating": row[7],
                    "material_type": "—"  # Можно позже заменить реальным значением, если будет в БД
                }
                for row in cursor.fetchall()
            ]

        except Exception as e:
            flash(f"Ошибка загрузки товаров: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    # Получаем корзину из сессии
    cart_items = session.get('cart', {'table': [], 'chair': []})

    return render_template('index.html', tables=tables, chairs=chairs, cart_items=cart_items)

@app.route('/item/<string:product_type>/<int:product_id>')
def item_detail(product_type, product_id):
    connection = create_connection()
    item = {}

    if connection:
        try:
            cursor = connection.cursor()
            if product_type == 'table':
                cursor.execute("""
                    SELECT id, name, description, price, image, quantity, size, leg_color, material_type
                    FROM tables
                    WHERE id = %s
                """, (product_id,))
                row = cursor.fetchone()
                if row:
                    item = {
                        "id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "price": row[3],
                        "image": row[4],
                        "quantity": row[5],
                        "size": row[6],
                        "leg_color": row[7],
                        "material_type": row[8],
                        "type": "table"
                    }

            elif product_type == 'chair':
                cursor.execute("""
                    SELECT id, name, description, price, image, leg_color, quantity, is_rotating
                    FROM chairs
                    WHERE id = %s
                """, (product_id,))
                row = cursor.fetchone()
                if row:
                    item = {
                        "id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "price": row[3],
                        "image": row[4],
                        "leg_color": row[5],
                        "quantity": row[6],
                        "is_rotating": row[7],
                        "type": "chair"
                    }

        except Exception as e:
            flash(f"Ошибка загрузки товара: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    if not item:
        flash("Товар не найден", "danger")
        return redirect(url_for('index'))

    return render_template('item.html', item=item)


@app.route('/autocomplete')
def autocomplete():
    query = request.args.get('q', '').strip()
    suggestions = []

    if query:
        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Ищем уникальные имена в обеих таблицах
                cursor.execute("""
                    SELECT DISTINCT name FROM tables WHERE name ILIKE %s LIMIT 5
                """, (f"%{query}%",))
                suggestions += [row[0] for row in cursor.fetchall()]

                cursor.execute("""
                    SELECT DISTINCT name FROM chairs WHERE name ILIKE %s LIMIT 5
                """, (f"%{query}%",))
                suggestions += [row[0] for row in cursor.fetchall()]

            except Exception as e:
                return jsonify({'error': str(e)}), 500
            finally:
                cursor.close()
                connection.close()

    return jsonify(suggestions)

@app.route('/search')
def search():
    """Обработка поиска товаров по названию и описанию."""
    query = request.args.get('q', '').strip()
    tables = []
    chairs = []

    if not query:
        flash("Введите запрос для поиска.", "warning")
        return redirect(url_for('index'))

    connection = create_connection()
    if connection:
        try:
            cursor = connection.cursor()

            # Поиск по таблице tables
            cursor.execute("""
                SELECT id, name, price, image, quantity, description, size, leg_color, material_type 
                FROM tables 
                WHERE name ILIKE %s OR description ILIKE %s
            """, (f"%{query}%", f"%{query}%"))
            tables = [
                {
                    "id": row[0],
                    "name": row[1],
                    "price": row[2],
                    "image": row[3],
                    "quantity": row[4],
                    "description": row[5],
                    "size": row[6],
                    "leg_color": row[7],
                    "material_type": row[8]
                }
                for row in cursor.fetchall()
            ]

            # Поиск по таблице chairs
            cursor.execute("""
                SELECT id, name, description, price, image, leg_color, quantity, is_rotating 
                FROM chairs 
                WHERE name ILIKE %s OR description ILIKE %s
            """, (f"%{query}%", f"%{query}%"))
            chairs = [
                {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "price": row[3],
                    "image": row[4],
                    "leg_color": row[5],
                    "quantity": row[6],
                    "is_rotating": row[7]
                }
                for row in cursor.fetchall()
            ]

        except Exception as e:
            flash(f"Ошибка при выполнении поиска: {e}", "danger")
        finally:
            cursor.close()
            connection.close()

    return render_template('search_results.html', query=query, tables=tables, chairs=chairs)

@app.context_processor
def inject_show_search():
    # URL путей, где нужна поисковая строка
    paths_with_search = ['/', '/catalog', '/tables', '/chairs']
    # Проверяем, совпадает ли текущий путь с одним из нужных
    show_search = request.path in paths_with_search
    return dict(show_search=show_search)


@app.route('/cart')
@login_required
def cart():
    connection = create_connection()
    cart_items = []
    total_price = 0

    if connection:
        try:
            cursor = connection.cursor()

            # Столы
            cursor.execute("""
                SELECT 
                    c.product_id, 
                    t.name, 
                    t.price, 
                    c.quantity, 
                    t.quantity AS stock, 
                    'table' AS type,
                    t.description,
                    t.image
                FROM cart c
                JOIN tables t ON c.product_id = t.id AND c.product_type = 'table'
                WHERE c.user_id = %s
            """, (current_user.id,))

            cart_items.extend([
                {"id": row[0], "name": row[1], "price": row[2], "quantity": row[3],
                 "total": row[2] * row[3], "stock": row[4], "type": row[5], "description": row[6], "image": row[7]}
                for row in cursor.fetchall()
            ])

            # Стулья
            cursor.execute("""
                SELECT 
                    c.product_id, 
                    ch.name, 
                    ch.price, 
                    c.quantity, 
                    ch.quantity AS stock, 
                    'chair' AS type,
                    ch.description,
                    ch.image
                FROM cart c
                JOIN chairs ch ON c.product_id = ch.id AND c.product_type = 'chair'
                WHERE c.user_id = %s
            """, (current_user.id,))

            cart_items.extend([
                {"id": row[0], "name": row[1], "price": row[2], "quantity": row[3],
                 "total": row[2] * row[3], "stock": row[4], "type": row[5], "description": row[6], "image": row[7]}
                for row in cursor.fetchall()
            ])

            # Общая стоимость
            total_price = sum(item["total"] for item in cart_items)

        except Exception as e:
            flash(f"Ошибка загрузки корзины: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/cart/add/<string:product_type>/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_type, product_id):
    connection = create_connection()

    if connection:
        try:
            cursor = connection.cursor()

            # Получение текущего остатка товара
            if product_type == "table":
                cursor.execute("SELECT quantity, name FROM tables WHERE id = %s", (product_id,))
            elif product_type == "chair":
                cursor.execute("SELECT quantity, name FROM chairs WHERE id = %s", (product_id,))
            else:
                msg = 'Некорректный тип товара!'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('catalog'))

            product = cursor.fetchone()
            if not product:
                msg = 'Товар не найден.'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": msg}), 404
                flash(msg, 'danger')
                return redirect(url_for('catalog'))

            stock_quantity, product_name = product

            # Получение количества в корзине текущего пользователя
            cursor.execute("""
                SELECT quantity FROM cart 
                WHERE user_id = %s AND product_id = %s AND product_type = %s
            """, (current_user.id, product_id, product_type))
            result = cursor.fetchone()
            current_quantity = result[0] if result else 0

            if current_quantity >= stock_quantity:
                msg = 'Недостаточно товара на складе.'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": msg}), 400
                flash(msg, 'warning')
                return redirect(url_for('catalog'))

            # Добавляем или обновляем позицию в корзине
            if result:
                cursor.execute("""
                    UPDATE cart SET quantity = quantity + 1
                    WHERE user_id = %s AND product_id = %s AND product_type = %s
                """, (current_user.id, product_id, product_type))
            else:
                cursor.execute("""
                    INSERT INTO cart (user_id, product_id, product_type, quantity)
                    VALUES (%s, %s, %s, 1)
                """, (current_user.id, product_id, product_type))

            connection.commit()
            msg = f'{product_name} добавлен в корзину!'
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"message": msg})
            flash(msg, 'success')

        except Exception as e:
            msg = f"Ошибка добавления в корзину: {e}"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": msg}), 500
            flash(msg, 'danger')
        finally:
            cursor.close()
            connection.close()

    # Если это AJAX — вернули ответ выше, сюда попадём только при обычном POST
    return redirect(request.referrer or url_for('catalog'))

@app.route('/cart/remove/<string:product_type>/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_type, product_id):
    connection = create_connection()

    if connection:
        try:
            cursor = connection.cursor()

            # Удаление позиции из корзины
            cursor.execute("""
                DELETE FROM cart 
                WHERE user_id = %s AND product_id = %s AND product_type = %s
            """, (current_user.id, product_id, product_type))

            connection.commit()
            flash('Товар удален из корзины.', 'success')

        except Exception as e:
            flash(f"Ошибка при удалении товара из корзины: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('cart'))

@app.route('/update_cart/<product_type>/<int:product_id>/<action>', methods=['POST'])
@login_required
def update_cart(product_type, product_id, action):
    connection = create_connection()

    if connection:
        try:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT quantity FROM cart 
                WHERE user_id = %s AND product_id = %s AND product_type = %s
            """, (current_user.id, product_id, product_type))
            result = cursor.fetchone()

            if not result:
                flash('Товар не найден в корзине.', 'warning')
                return redirect(url_for('cart'))

            current_quantity = result[0]

            if action == 'increase':
                if product_type == 'table':
                    cursor.execute("SELECT quantity FROM tables WHERE id = %s", (product_id,))
                elif product_type == 'chair':
                    cursor.execute("SELECT quantity FROM chairs WHERE id = %s", (product_id,))
                else:
                    flash('Некорректный тип товара.', 'danger')
                    return redirect(url_for('cart'))

                stock = cursor.fetchone()
                if stock and current_quantity < stock[0]:
                    cursor.execute("""
                        UPDATE cart SET quantity = quantity + 1
                        WHERE user_id = %s AND product_id = %s AND product_type = %s
                    """, (current_user.id, product_id, product_type))
                else:
                    flash('Недостаточно товара на складе.', 'warning')

            elif action == 'decrease':
                if current_quantity > 1:
                    cursor.execute("""
                        UPDATE cart SET quantity = quantity - 1
                        WHERE user_id = %s AND product_id = %s AND product_type = %s
                    """, (current_user.id, product_id, product_type))
                else:
                    # Удаляем товар, если количество стало 0
                    cursor.execute("""
                        DELETE FROM cart 
                        WHERE user_id = %s AND product_id = %s AND product_type = %s
                    """, (current_user.id, product_id, product_type))

            connection.commit()

        except Exception as e:
            flash(f'Ошибка при обновлении корзины: {e}', 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('cart'))

@app.route('/product/<string:product_type>/<int:product_id>')
def product_detail(product_type, product_id):
    """Детальная страница товара (стол или стул)."""
    connection = create_connection()
    product = None

    if connection:
        try:
            cursor = connection.cursor()

            if product_type == "table":
                cursor.execute("""
                    SELECT id, name, price, image, description, size, color, leg_color, material_type, quantity
                    FROM tables WHERE id = %s
                """, (product_id,))
                row = cursor.fetchone()
                if row:
                    product = {
                        "id": row[0], "name": row[1], "price": row[2], "image": row[3],
                        "description": row[4], "size": row[5], "color": row[6],
                        "leg_color": row[7], "material_type": row[8], "quantity": row[9], "type": "table"
                    }

            elif product_type == "chair":
                cursor.execute("""
                    SELECT id, name, price, image, description, is_rotating, color, leg_color, material_type, quantity
                    FROM chairs WHERE id = %s
                """, (product_id,))
                row = cursor.fetchone()
                if row:
                    product = {
                        "id": row[0], "name": row[1], "price": row[2], "image": row[3],
                        "description": row[4], "is_rotating": row[5], "color": row[6],
                        "leg_color": row[7], "material_type": row[8], "quantity": row[9], "type": "chair"
                    }

        except Exception as e:
            flash(f"Ошибка загрузки товара: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template('product_detail.html', product=product)

@app.route('/catalog')
def catalog():
    """Каталог товаров (столы и стулья)."""
    connection = create_connection()
    tables = []
    chairs = []

    if connection:
        try:
            cursor = connection.cursor()

            # Запрос для столов с description и material_type
            cursor.execute(
                """
                SELECT id, name, description, material_type, price, image, quantity, size, leg_color
                FROM tables
                """
            )
            tables = [
                {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "material_type": row[3],
                    "price": row[4],
                    "image": row[5],
                    "quantity": row[6],
                    "size": row[7],
                    "leg_color": row[8],
                }
                for row in cursor.fetchall()
            ]

            # Запрос для стульев (если есть description/material_type — добавить их тоже)
            cursor.execute(
                """
                SELECT id, name, price, image, quantity, color, leg_color, is_rotating, material_type, description
                FROM chairs
                """
            )
            chairs = [
                {
                    "id": row[0],
                    "name": row[1],
                    "price": row[2],
                    "image": row[3],
                    "quantity": row[4],
                    "color": row[5],
                    "leg_color": row[6],
                    "is_rotating": row[7],
                    "material_type": row[8],
                    "description": row[9],
                }
                for row in cursor.fetchall()
            ]

        except Exception as e:
            flash(f"Ошибка загрузки товаров: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template('catalog.html', tables=tables, chairs=chairs)

def determine_shape(size_str):
    # размер приходит в формате "120x120" или "238x118"
    parts = size_str.split('x')
    if len(parts) == 2 and parts[0] == parts[1]:
        return 'Круглый'
    return 'Прямоугольный'

@app.route('/tables')
def tables():
    connection = create_connection()
    tables = []
    min_price = max_price = None
    leg_colors = []
    material_types = []
    shapes = ['Круглый', 'Прямоугольный']

    MATERIAL_DISPLAY = {
        "WOOD": "Дерево",
        "GLASS": "Стекло",
        "CER": "Керамика"
    }

    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT id, name, price, image, quantity, description, size, leg_color, material_type FROM tables")
            rows = cursor.fetchall()
            tables = [
                {
                    "id": row[0],
                    "name": row[1],
                    "price": float(row[2]),
                    "image": row[3],
                    "quantity": row[4],
                    "description": row[5],
                    "size": row[6],
                    "leg_color": row[7] if row[7] else 'Не указан',
                    "material_type": row[8] if row[8] else 'UNKNOWN',
                    "material_display": MATERIAL_DISPLAY.get(row[8], row[8]),
                    "shape": determine_shape(row[6]) if row[6] else 'Не указан'
                }
                for row in rows
            ]

            cursor.execute("SELECT MIN(price), MAX(price) FROM tables")
            min_price, max_price = cursor.fetchone()
            if max_price is not None:
                max_price = float(max_price) + 1000

            cursor.execute("SELECT DISTINCT leg_color FROM tables WHERE leg_color IS NOT NULL AND leg_color != ''")
            leg_colors = [row[0] for row in cursor.fetchall()]

            cursor.execute("SELECT DISTINCT material_type FROM tables WHERE material_type IS NOT NULL AND material_type != ''")
            raw_materials = [row[0] for row in cursor.fetchall()]
            material_types = [
                {"code": mat, "name": MATERIAL_DISPLAY.get(mat, mat)}
                for mat in raw_materials
            ]
        except Exception as e:
            flash(f"Ошибка загрузки столов: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template(
        'tables.html',
        tables=tables,
        min_price=min_price,
        max_price=max_price,
        leg_colors=leg_colors,
        material_types=material_types,
        shapes=shapes,
        request=request
    )

@app.route('/table/<int:table_id>')
def table_detail(table_id):
    connection = create_connection()
    MATERIAL_DISPLAY = {
        "WOOD": "Дерево",
        "GLASS": "Стекло",
        "CER": "Керамика"
    }
    table = None
    recommendations = []
    table_specs = None

    try:
        cursor = connection.cursor()
        # Получаем данные выбранного стола
        cursor.execute("""
            SELECT id, name, price, image, quantity, description, size, leg_color, material_type
            FROM tables WHERE id = %s
        """, (table_id,))
        row = cursor.fetchone()

        if not row:
            flash("Стол не найден.", "warning")
            return redirect(url_for('tables'))

        # Заполняем данные стола
        table = {
            "id": row[0],
            "name": row[1],
            "price": float(row[2]),
            "image": row[3],
            "quantity": row[4],
            "description": row[5],
            "size": row[6],
            "leg_color": row[7] if row[7] else 'Не указан',
            "material_type": row[8] if row[8] else 'UNKNOWN',
            "material_display": MATERIAL_DISPLAY.get(row[8], row[8]),
            "shape": determine_shape(row[6]) if row[6] else 'Не указан'
        }

        # Получаем характеристики из table_specs
        cursor.execute("""
            SELECT width_mm, depth_mm, height_mm, country_of_origin
            FROM table_specs
            WHERE table_id = %s
        """, (table_id,))
        spec_row = cursor.fetchone()
        if spec_row:
            table_specs = {
                "width_mm": spec_row[0],
                "depth_mm": spec_row[1],
                "height_mm": spec_row[2],
                "country_of_origin": spec_row[3]
            }

        # Получаем все остальные столы, кроме текущего
        cursor.execute("""
            SELECT id, name, price, image, quantity, description, size, leg_color, material_type
            FROM tables
            WHERE id != %s
        """, (table_id,))
        all_others = cursor.fetchall()

        def shape_of_size(size_str):
            return determine_shape(size_str)

        # Фильтруем рекомендации по материалу или форме
        recommendations = [
            {
                "id": r[0],
                "name": r[1],
                "price": float(r[2]),
                "image": r[3],
                "quantity": r[4],
                "description": r[5],
                "size": r[6],
                "leg_color": r[7] if r[7] else 'Не указан',
                "material_type": r[8] if r[8] else 'UNKNOWN',
                "material_display": MATERIAL_DISPLAY.get(r[8], r[8]),
                "shape": shape_of_size(r[6]) if r[6] else 'Не указан'
            }
            for r in all_others
            if r[8] == table['material_type'] or shape_of_size(r[6]) == table['shape']
        ][:4]

    except Exception as e:
        flash(f"Ошибка загрузки данных стола: {e}", 'danger')
        return redirect(url_for('tables'))
    finally:
        cursor.close()
        connection.close()

    return render_template(
        'table_detail.html',
        table=table,
        recommendations=recommendations,
        table_specs=table_specs  # ← передаём в шаблон
    )

@app.route('/chairs')
def chairs():
    connection = create_connection()
    chairs = []
    min_price = max_price = None
    leg_colors = []
    material_types = []

    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT id, name, description, price, image, leg_color, quantity, material_type, is_rotating, armrest 
                FROM chairs
            """)
            chairs = [
                {
                    "id": row[0], "name": row[1], "description": row[2], "price": float(row[3]),
                    "image": row[4], "leg_color": row[5], "quantity": row[6], "material_type": row[7],
                    "is_rotating": row[8], "armrest": row[9]
                }
                for row in cursor.fetchall()
            ]
            cursor.execute("SELECT MIN(price), MAX(price) FROM chairs")
            min_price, max_price = cursor.fetchone()

            if max_price is not None:
                max_price = float(max_price) + 1000

            cursor.execute("SELECT DISTINCT leg_color FROM chairs")
            leg_colors = [row[0] for row in cursor.fetchall()]

            cursor.execute("SELECT DISTINCT material_type FROM chairs")
            material_types = [row[0] for row in cursor.fetchall()]
        except Exception as e:
            flash(f"Ошибка загрузки стульев: {e}", 'danger')
        finally:
            cursor.close()
            connection.close()

    return render_template('chairs.html', chairs=chairs, min_price=min_price, max_price=max_price,
                           leg_colors=leg_colors, material_types=material_types)

@app.route('/chair/<int:chair_id>')
def chair_detail(chair_id):
    connection = create_connection()
    chair = None
    recommendations = []

    if connection:
        try:
            cursor = connection.cursor()

            # Получаем данные стула с JOIN на chair_specs
            cursor.execute("""
                SELECT c.id, c.name, c.description, c.price, c.image, c.leg_color, c.quantity,
                       c.material_type, c.is_rotating, c.color, c.armrest,
                       cs.width_mm, cs.depth_mm, cs.height_mm, cs.seat_width_mm, cs.seat_depth_mm, cs.seat_height_mm, cs.country_of_origin
                FROM chairs c
                LEFT JOIN chair_specs cs ON c.id = cs.chair_id
                WHERE c.id = %s
            """, (chair_id,))
            row = cursor.fetchone()

            if not row:
                flash("Стул не найден", "warning")
                return redirect(url_for('chairs'))

            chair = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "price": float(row[3]),
                "image": row[4],
                "leg_color": row[5] or "Не указан",
                "quantity": row[6],
                "material_type": row[7] or "Не указан",
                "is_rotating": row[8],
                "color": row[9] or "Не указан",
                "armrest": row[10],
                "width_mm": row[11],
                "depth_mm": row[12],
                "height_mm": row[13],
                "seat_width_mm": row[14],
                "seat_depth_mm": row[15],
                "seat_height_mm": row[16],
                "country_of_origin": row[17] or "Не указан"
            }

            # Рекомендации по цвету (макс 4)
            cursor.execute("""
                SELECT id, name, description, price, image
                FROM chairs
                WHERE color = %s AND id != %s
                LIMIT 4
            """, (chair["color"], chair_id))
            recs = cursor.fetchall()

            recommendations = [
                {"id": r[0], "name": r[1], "description": r[2], "price": float(r[3]), "image": r[4]}
                for r in recs
            ]

            # Если рекомендаций нет, по имени (макс 4)
            if not recommendations:
                cursor.execute("""
                    SELECT id, name, description, price, image
                    FROM chairs
                    WHERE name = %s AND id != %s
                    LIMIT 4
                """, (chair["name"], chair_id))
                recs = cursor.fetchall()
                recommendations = [
                    {"id": r[0], "name": r[1], "description": r[2], "price": float(r[3]), "image": r[4]}
                    for r in recs
                ]

            # Если меньше 4 — добавляем случайные, исключая уже взятых и текущий
            if len(recommendations) < 4:
                exclude_ids = [chair_id] + [r["id"] for r in recommendations]
                placeholders = ','.join(['%s'] * len(exclude_ids))
                limit = 4 - len(recommendations)
                cursor.execute(f"""
                    SELECT id, name, description, price, image
                    FROM chairs
                    WHERE id NOT IN ({placeholders})
                    ORDER BY RANDOM()
                    LIMIT %s
                """, (*exclude_ids, limit))
                additional = cursor.fetchall()
                recommendations.extend([
                    {"id": r[0], "name": r[1], "description": r[2], "price": float(r[3]), "image": r[4]}
                    for r in additional
                ])

        except Exception as e:
            flash(f"Ошибка при загрузке стула: {e}", "danger")
            return redirect(url_for('chairs'))
        finally:
            cursor.close()
            connection.close()

    return render_template('chair_detail.html', chair=chair, recommendations=recommendations)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Логика для сброса пароля
    return render_template('reset_password.html', token=token)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    connection = create_connection()

    if request.method == 'POST':
        confirm_order = request.form.get('confirm_order')
        if not confirm_order:
            flash("Пожалуйста, подтвердите заказ.", "warning")
            return redirect(url_for('checkout'))

        last_name = request.form.get('last_name')
        first_name = request.form.get('first_name')
        middle_name = request.form.get('middle_name', '')
        phone = request.form.get('phone')
        email = request.form.get('email')
        delivery = request.form.get('delivery') == '1'

        try:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT c.product_id, c.product_type, c.quantity,
                       COALESCE(t.name, ch.name),
                       COALESCE(t.description, ch.description),
                       COALESCE(t.price, ch.price)
                FROM cart c
                LEFT JOIN tables t ON c.product_type = 'table' AND c.product_id = t.id
                LEFT JOIN chairs ch ON c.product_type = 'chair' AND c.product_id = ch.id
                WHERE c.user_id = %s
            """, (current_user.id if current_user.is_authenticated else -1,))
            items = cursor.fetchall()

            if not items:
                flash("Корзина пуста.", "warning")
                return redirect(url_for('cart'))

            total_price = 0
            errors = []
            cart_data = []

            for product_id, product_type, quantity, name, description, price in items:
                if product_type == 'table':
                    cursor.execute("SELECT quantity FROM tables WHERE id = %s", (product_id,))
                else:
                    cursor.execute("SELECT quantity FROM chairs WHERE id = %s", (product_id,))
                available_quantity = cursor.fetchone()[0]

                if quantity > available_quantity:
                    errors.append(f"Недостаточно товара «{name}». В наличии: {available_quantity} шт.")
                    continue

                subtotal = float(price) * quantity
                total_price += subtotal

                cart_data.append({
                    'product_id': product_id,
                    'product_type': product_type,
                    'name': name,
                    'description': description,
                    'price': float(price),
                    'quantity': quantity
                })

            if delivery:
                total_price += 990

            if errors:
                for error in errors:
                    flash(error, "danger")
                return redirect(url_for('checkout'))

            token = serializer.dumps(email, salt='email-confirm')
            user_id = current_user.id if current_user.is_authenticated else None

            # Сохраняем в pending_orders
            cursor.execute("""
                INSERT INTO pending_orders (
                    user_id, last_name, first_name, middle_name, phone, email,
                    delivery, delivery_price, total_price, confirmation_token
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                user_id, last_name, first_name, middle_name, phone, email,
                delivery, 990 if delivery else 0, total_price, token
            ))
            pending_id = cursor.fetchone()[0]

            if delivery:
                area = request.form.get('area')
                town = request.form.get('town')
                locality = request.form.get('locality')
                street = request.form.get('street')
                house = request.form.get('house')
                flat = request.form.get('flat')
                floor = request.form.get('floor')

                cursor.execute("""
                    INSERT INTO address (
                        area, town, locality, street, house, flat, floor,
                        delivery, pending_order_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, %s)
                """, (area, town, locality, street, house, flat, floor, pending_id))

            session['pending_cart'] = json.dumps(cart_data)
            session['pending_id'] = pending_id

            confirm_url = url_for('confirm_order', token=token, _external=True)
            send_email(email, 'Подтвердите ваш заказ', f"Для подтверждения заказа перейдите по ссылке: {confirm_url}")

            connection.commit()
            flash("Письмо с подтверждением заказа отправлено на вашу почту.", "info")
            return redirect(url_for('profile'))

        except Exception as e:
            connection.rollback()
            flash("Ошибка при сохранении заказа.", "danger")
            print("Ошибка:", e)
            return redirect(url_for('checkout'))

        finally:
            cursor.close()
            connection.close()

    else:
        cart_items = []
        total_price = 0

        try:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT c.product_id, c.product_type, c.quantity,
                       COALESCE(t.name, ch.name),
                       COALESCE(t.description, ch.description),
                       COALESCE(t.price, ch.price),
                       COALESCE(t.image, ch.image)
                FROM cart c
                LEFT JOIN tables t ON c.product_type = 'table' AND c.product_id = t.id
                LEFT JOIN chairs ch ON c.product_type = 'chair' AND c.product_id = ch.id
                WHERE c.user_id = %s
            """, (current_user.id if current_user.is_authenticated else -1,))
            items = cursor.fetchall()

            for item in items:
                product_id, product_type, quantity, name, description, price, image = item
                subtotal = float(price) * quantity
                total_price += subtotal
                cart_items.append({
                    'product_id': product_id,
                    'product_type': product_type,
                    'name': name,
                    'description': description,
                    'price': float(price),
                    'image': image,
                    'quantity': quantity
                })

        finally:
            cursor.close()
            connection.close()

        return render_template('checkout.html', cart_items=cart_items, total_price=total_price)

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    order_id = request.args.get('order_id', type=int)
    if not order_id:
        flash("Пожалуйста, сначала оформите заказ.", "warning")
        return redirect(url_for('profile'))

    connection = create_connection()
    if not connection:
        flash("Ошибка подключения к базе данных", "danger")
        return redirect(url_for('index'))

    cursor = connection.cursor()

    try:
        # Проверяем, что заказ существует и принадлежит пользователю
        cursor.execute(
            "SELECT is_paid, total_price, created_at FROM orders WHERE id = %s AND user_id = %s",
            (order_id, current_user.id)
        )
        order = cursor.fetchone()
        if not order:
            flash("Заказ не найден.", "warning")
            return redirect(url_for('profile'))

        is_paid, total_price, created_at = order

        if is_paid:
            flash("Заказ уже оплачен.", "info")
            return redirect(url_for('profile'))

        if request.method == 'POST':
            # Обновляем статус оплаты
            cursor.execute(
                "UPDATE orders SET is_paid = TRUE WHERE id = %s",
                (order_id,)
            )
            connection.commit()

            flash("Оплата прошла успешно!", "success")

            # Очистка корзины
            session.pop('cart', None)
            session.pop('pending_id', None)
            session.pop('pending_cart', None)

            return redirect(url_for('index'))

        # GET - показываем страницу оплаты с данными заказа
        order_data = {
            'id': order_id,
            'total_price': total_price,
            'created_at': created_at
        }
        return render_template('payment.html', order=order_data)

    finally:
        cursor.close()
        connection.close()

@app.route('/confirm/<token>')
def confirm_order(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash("Ссылка подтверждения недействительна или устарела.", "danger")
        return redirect(url_for('index'))

    connection = create_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT * FROM pending_orders WHERE email = %s AND confirmation_token = %s AND confirmed = FALSE", (email, token))
        pending = cursor.fetchone()

        if not pending:
            flash("Заказ не найден или уже подтвержден.", "warning")
            return redirect(url_for('index'))

        (pending_id, user_id, last_name, first_name, middle_name, phone, email,
         delivery, delivery_price, total_price, created_at, confirmation_token, confirmed) = pending

        # Если user_id отсутствует, а пользователь авторизован — назначаем
        if not user_id:
            if current_user.is_authenticated:
                user_id = current_user.id
            else:
                flash("Войдите в аккаунт перед подтверждением заказа.", "warning")
                return redirect(url_for('login'))

        cart_data_json = session.get('pending_cart')
        if not cart_data_json:
            flash("Не удалось получить данные корзины.", "danger")
            return redirect(url_for('index'))

        cart_data = json.loads(cart_data_json)

        cursor.execute("""
            INSERT INTO orders (user_id, last_name, first_name, middle_name, phone, email, delivery, total_price, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (user_id, last_name, first_name, middle_name, phone, email, delivery, total_price))
        order_id = cursor.fetchone()[0]

        for item in cart_data:
            product_id = item['product_id']
            product_type = item['product_type']
            name = item['name']
            description = item['description']
            price = item['price']
            quantity = item['quantity']

            if product_type == 'table':
                cursor.execute("UPDATE tables SET quantity = quantity - %s WHERE id = %s", (quantity, product_id))
            elif product_type == 'chair':
                cursor.execute("UPDATE chairs SET quantity = quantity - %s WHERE id = %s", (quantity, product_id))

            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_type, name, description, price, quantity)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (order_id, product_id, product_type, name, description, price, quantity))

        cursor.execute("UPDATE pending_orders SET confirmed = TRUE WHERE id = %s", (pending_id,))
        cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))

        connection.commit()
        session.pop('pending_cart', None)
        session.pop('pending_id', None)

        flash("Ваш заказ успешно подтвержден и оформлен!", "success")
    except Exception as e:
        connection.rollback()
        flash("Ошибка при подтверждении заказа.", "danger")
        print("Ошибка:", e)
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('index'))

@app.route('/pay/<int:order_id>', methods=['POST'])
@login_required
def pay_order(order_id):
    conn = create_connection()
    if not conn:
        flash("Не удалось подключиться к базе данных", "danger")
        return redirect(url_for('profile'))

    try:
        cur = conn.cursor()

        # Проверяем, принадлежит ли заказ текущему пользователю
        cur.execute("SELECT user_id FROM orders WHERE id = %s", (order_id,))
        result = cur.fetchone()
        #if not result or result[0] != current_user.id:
        #    flash("Вы не можете оплатить этот заказ", "danger")
        #    return redirect(url_for('profile'))

        # Устанавливаем is_paid = TRUE
        cur.execute('UPDATE orders SET is_paid = TRUE WHERE id = %s', (order_id,))
        conn.commit()
        flash('Оплата прошла успешно!', 'success')

    except Exception as e:
        conn.rollback()
        flash(f"Ошибка при оплате: {e}", "danger")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('profile'))


def send_email(to_email, subject, body):
    msg = Message(subject=subject,
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email])
    msg.body = body
    mail.send(msg)

def home():
    tables = Table.query.all()
    chairs = Chair.query.all()
    cart = session.get('cart', {})
    cart_items = {
        'table': [int(i) for i in cart.get('table', [])],
        'chair': [int(i) for i in cart.get('chair', [])]
    }
    return render_template('home.html', tables=tables, chairs=chairs, cart_items=cart_items)


if __name__ == '__main__':
    app.run(debug=True)
