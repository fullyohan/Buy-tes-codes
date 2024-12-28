import os
from flask import Flask, render_template, session, redirect, url_for, request, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from flask import Flask, render_template, session, redirect, url_for, request, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Email
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
from flask_mail import Mail, Message
import random
import string
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'Flask/static/images/'
csrf = CSRFProtect(app)
csrf = CSRFProtect(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'buytescodes225@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Use App Password if 2-Step Verification is enabled

mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'google.login'

google_bp = make_google_blueprint(
    client_id='661154987586-s78fjavpng86h7ep2g7qku3i9ma05aep.apps.googleusercontent.com',
    client_secret='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',
    redirect_to='google_login',
    redirect_url='http://127.0.0.1:5000/google_login',
    scope=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']  # Ensure email and profile scopes are included
)
app.register_blueprint(google_bp, url_prefix='/google_login')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Mock data
products = [
    {"id": 1, "name": "Super Mario Odyssey", "category": "recent_products", "platform": "nintendo", "price": 1000, "rating": 4.5, "image": "SWITCH/smo.png", "codes": ["CODE1", "CODE2", "CODE3"]},
    {"id": 2, "name": "Minecraft", "category": "high_rated_products", "platform": "playstation", "price": 2000, "rating": 4.0, "image": "PLAY/minecraft.png", "codes": ["CODE4", "CODE5", "CODE6"]},
    # ... more products ...
]

# Helper functions
def calculate_total_price(cart_items):
    return sum(item['price'] * item['quantity'] for item in cart_items)

def find_product_by_id(product_id):
    return next((product for product in products if product['id'] == product_id), None)

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('Tu dois de connecter pour y acceder .', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__  # Ensure unique endpoint name
    return decorated_function

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session['username'] != 'admin':
            flash('Tu dois etre admin :/.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__  # Ensure unique endpoint name
    return decorated_function

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_unique_code(existing_codes):
    while True:
        new_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        if new_code not in existing_codes:
            return new_code

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Le mot de passe doit contenir au moins 8 caractères.'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)', message='Le mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule et un chiffre.')
    ])
    submit = SubmitField('Register')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class NewPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Le mot de passe doit contenir au moins 8 caractères.'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)', message='Le mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule et un chiffre.')
    ])
    submit = SubmitField('Set New Password')

# Routes
@app.route('/')
def index():
    print("Index route called")  # Debug statement
    recent_products = [p for p in products if p['category'] == 'recent_products']
    high_rated_products = [p for p in products if p['category'] == 'high_rated_products']
    cart_items = session.get('cart_items', [])
    total_price = calculate_total_price(cart_items)
    transaction_id = str(random.randint(100000000, 999999999))
    print(f"Recent Products: {recent_products}")  # Debug statement
    print(f"High Rated Products: {high_rated_products}")  # Debug statement
    print(f"Cart Items: {cart_items}")  # Debug statement
    print(f"Total Price: {total_price}")  # Debug statement
    return render_template('index.html', 
                           recent_products=recent_products, 
                           high_rated_products=high_rated_products, 
                           cart_items=cart_items, 
                           total_price=total_price,
                           cinetpay_apikey=os.getenv('CINETPAY_APIKEY', '16490420165f879ee4f1253.15350040'),
                           cinetpay_site_id=os.getenv('CINETPAY_SITE_ID', '20459131176727677fb6e1e7.60789362'),
                           transaction_id=transaction_id)

@app.route('/products')
def products_view():
    print("Products route called")  # Debug statement
    print(f"Products: {products}")  # Debug statement
    return render_template('products.html', products=products)

@app.route('/shop/<category>')
def shop_category(category):
    print(f"Shop category route called for category: {category}")  # Debug statement
    category_products = [product for product in products if product['category'].lower() == category.lower()]
    print(f"Category Products: {category_products}")  # Debug statement
    return render_template('category.html', products=category_products, category=category)

@app.route('/filter', methods=['GET'])
def filter_products():
    min_price = request.args.get('min_price', type=int, default=0)
    max_price = request.args.get('max_price', type=int, default=float('inf'))
    filtered_products = [product for product in products if min_price <= product['price'] <= max_price]
    return render_template('products.html', products=filtered_products)

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        if any(user['username'] == username for user in session.get('users', [])):
            flash('Le nom d\'utilisateur existe déjà. Veuillez en choisir un autre.', 'danger')
        elif any(user['email'] == email for user in session.get('users', [])):
            flash('Cette adresse e-mail existe déjà. Veuillez en choisir une autre.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = {"username": username, "email": email, "password": hashed_password}  # Include phone number
            users = session.get('users', [])
            users.append(new_user)
            session['users'] = users
            flash('Création de compte réussie. Connectez-vous maintenant.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = next((user for user in session.get('users', []) if user['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            flash('Vous êtes maintenant connecté.', 'success')
            if username == 'admin':
                return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard if admin
            else:
                return redirect(url_for('index'))  # Redirect to index page if not admin
        else:
            flash('Identifiants incorrects. Veuillez réessayer.', 'danger')
    return render_template('form.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('Vous vous êtes déconnecté avec succès.', 'success')
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = next((user for user in session.get('users', []) if user['email'] == email), None)
        if user:
            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            session['reset_email'] = email
            
            msg = MIMEMultipart()
            msg['From'] = 'buytescodes225@gmail.com'
            msg['To'] = email
            msg['Subject'] = 'Code de vérification de réinitialisation du mot de passe'
            message = f'Votre code de vérification est : {verification_code}'
            msg.attach(MIMEText(message))
            
            try:
                mailserver = smtplib.SMTP('smtp.gmail.com', 587)
                mailserver.ehlo()
                mailserver.starttls()
                mailserver.ehlo()
                mailserver.login('buytescodes225@gmail.com', 'your_app_password')  # Use App Password if 2-Step Verification is enabled
                mailserver.sendmail('buytescodes225@gmail.com', email, msg.as_string())
                mailserver.quit()
                flash('Un code de vérification a été envoyé à votre adresse e-mail.', 'success')
            except smtplib.SMTPException as e:
                flash(f'Échec de l\'envoi de l\'e-mail : {str(e)}', 'danger')
                print(f'Échec de l\'envoi de l\'e-mail : {str(e)}')
            return redirect(url_for('verify_code'))
        else:
            flash('Aucun compte trouvé avec cette adresse e-mail.', 'danger')
    return render_template('reset_password.html', form=form)

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    form = FlaskForm()  # Create an instance of FlaskForm
    if request.method == 'POST':
        code = request.form.get('code')
        if code == session.get('verification_code'):
            flash('Code vérifié avec succès. Vous pouvez maintenant réinitialiser votre mot de passe.', 'success')
            return redirect(url_for('new_password'))
        else:
            flash('Code de vérification incorrect.', 'danger')
    return render_template('verify_code.html', form=form)

@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    form = NewPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        email = session.get('reset_email')
        user = next((user for user in session.get('users', []) if user['email'] == email), None)
        if user:
            user['password'] = hashed_password
            flash('Votre mot de passe a été réinitialisé avec succès.', 'success')
            return redirect(url_for('login'))
    return render_template('new_password.html', form=form)

@app.route('/update_cart_quantity', methods=['POST'])
def update_cart_quantity():
    product_id = request.form.get('product_id', type=int)
    new_quantity = request.form.get('quantity', type=int)
    cart_items = session.get('cart_items', [])
    for item in cart_items:
        if item['id'] == product_id:
            item['quantity'] = new_quantity
            break
    session['cart_items'] = cart_items
    total_price = calculate_total_price(cart_items)
    session['total_price'] = total_price
    return jsonify({'success': True, 'total_price': total_price})

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = find_product_by_id(product_id)
    if product:
        cart_items = session.get('cart_items', [])
        for item in cart_items:
            if item['id'] == product_id:
                item['quantity'] += 1
                break
        else:
            cart_items.append({"id": product_id, "name": product['name'], "price": product['price'], "quantity": 1, "image_url": product['image']})
        session['cart_items'] = cart_items
        total_price = calculate_total_price(cart_items)
        session['total_price'] = total_price
        flash('Produit ajouté au panier', 'success')
    else:
        flash('Produit non trouvé', 'danger')
    return redirect(url_for('index'))

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart_items = session.get('cart_items', [])
    cart_items = [item for item in cart_items if item['id'] != product_id]
    session['cart_items'] = cart_items
    total_price = calculate_total_price(cart_items)
    session['total_price'] = total_price
    flash('Produit retiré du panier', 'success')
    return redirect(url_for('index'))

@app.route('/get_cart_contents', methods=['GET'])
def get_cart_contents():
    user_id = session.get('user_id')
    cart_items = session.get('cart_items', [])
    total_price = calculate_total_price(cart_items)
    return jsonify({'cart_items': cart_items, 'total_price': total_price})

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    form = LoginForm()  # Add form instance
    return render_template('admin/dashboard.html', form=form)  # Pass form to template

@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_products():
    form = LoginForm()  # Add form instance
    if request.method == 'POST':
        product_name = request.form['product_name']
        product_category = request.form['product_category']
        product_platform = request.form['product_platform']
        product_price = float(request.form['product_price'])
        product_rating = float(request.form['product_rating'])
        product_image = request.files['product_image']
        product_codes = request.form['product_codes'].split(',')

        # Save the uploaded image
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product_image.filename)
        product_image.save(image_path)

        # Add product to the database (mocked as a list here)
        new_id = max(p['id'] for p in products) + 1 if products else 1
        products.append({
            "id": new_id, 
            "name": product_name, 
            "category": product_category, 
            "platform": product_platform,
            "price": product_price, 
            "rating": product_rating, 
            "image": product_image.filename,
            "codes": product_codes
        })
        
        return redirect(url_for('admin_products'))
    return render_template('admin/products.html', products=products, form=form)  # Pass form to template

@app.route('/add_product', methods=['POST'])
@login_required
@admin_required
def add_product():
    product_name = request.form['product_name']
    product_category = request.form['product_category']
    product_platform = request.form['product_platform']
    product_price = int(request.form['product_price'])
    product_rating = float(request.form['product_rating'])
    product_image = request.files['product_image']

    # Save the uploaded image
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], product_image.filename)
    product_image.save(image_path)

    # Add product to the database (mocked as a list here)
    new_id = max(p['id'] for p in products) + 1 if products else 1
    products.append({
        "id": new_id, 
        "name": product_name, 
        "category": product_category, 
        "platform": product_platform,
        "price": product_price, 
        "rating": product_rating, 
        "image": product_image.filename
    })
    
    return redirect(url_for('admin_products'))

@app.route('/purchase/<int:product_id>', methods=['POST'])
@login_required
def purchase(product_id):
    product = find_product_by_id(product_id)
    if product and product['codes']:
        used_code = product['codes'].pop(0)
        if not product['codes']:
            # Remove the product if no more codes are left
            global products
            products = [p for p in products if p['id'] != product_id]
            flash(f'Achat réussi ! Votre code : {used_code}. Le produit est maintenant en rupture de stock et a été retiré.', 'success')
        else:
            flash(f'Achat réussi ! Votre code : {used_code}', 'success')
    else:
        flash('Produit non disponible ou en rupture de stock', 'danger')
    return redirect(url_for('index'))

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def delete_product(product_id):
    form = LoginForm()  # Add form instance
    global products
    products = [product for product in products if product['id'] != product_id]
    flash('Produit supprimé avec succès.', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    form = LoginForm()  # Add form instance
    # Mocked orders list
    orders = [
        {"id": 1, "product_name": "Game A", "quantity": 2, "total_price": 20},
        {"id": 2, "product_name": "Game B", "quantity": 1, "total_price": 20},
    ]
    return render_template('admin/orders.html', orders=orders, form=form)  # Pass form to template

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    form = LoginForm()  # Add form instance
    # Mocked users list
    users = session.get('users', [])
    return render_template('admin/users.html', users=users, form=form)  # Pass form to template

@app.route('/pay', methods=['POST'])
def pay():
    user_id = session.get('user_id')
    cart_items = session.get('cart_items', [])
    total_amount = calculate_total_price(cart_items)
    print(f"Total amount to be paid: {total_amount}")  # Debug statement

    # Mock payment API call
    try:
        response = requests.post(
            'https://api-checkout.cinetpay.com/v2/payment',
            headers={
                'Content-Type': 'application/json',
                'Authorization': os.getenv('CINETPAY_AUTH_KEY', 'your_cinetpay_auth_key')  # Use environment variable
            },
            json={
                'amount': total_amount,
                'currency': 'XOF',
                'reference': 'YOUR_REFERENCE'
            }
        )
        if response.status_code == 200:
            session.pop('cart_items', None)  # Clear cart
            return jsonify({'message': 'Payment successful!'})
        print("Payment failed")  # Debug statement
        return jsonify({'error': 'Payment failed.'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('searchKeyword', '')  # Updated query parameter name
    print(f"Search query: {query}")  # Debug statement
    if query:
        search_results = [product for product in products if query.lower() in product['name'].lower()]
    else:
        search_results = products  # Show all products if query is empty
    print(f"Search Results: {search_results}")  # Debug statement
    return render_template('search_results.html', products=search_results, query=query)

@app.route('/filter_platform', methods=['GET'])
def filter_platform():
    platform = request.args.get('platform', '').lower()
    filtered_products = [product for product in products if product['platform'].lower() == platform]
    return render_template('products.html', products=filtered_products)

@app.route('/contact')
def contact():
    return render_template('contacts.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/google_login')
def google_login():
    if not google.authorized:
        print("Google not authorized")
        return redirect(url_for('google.login'))
    resp = google.get('/oauth2/v2/userinfo')
    if not resp.ok:
        print(f"Google OAuth response not OK: {resp.text}")
        return redirect(url_for('index'))
    google_info = resp.json()
    print(f"Google info: {google_info}")
    google_id = google_info.get('id')
    email = google_info.get('email')
    name = google_info.get('name')
    
    if not email:
        print("Email not found in Google OAuth response")
        flash('Échec de la récupération de l\'e-mail du compte Google.', 'danger')
        return redirect(url_for('index'))
    
    # Create a unique username using the Google account name
    base_username = name.replace(" ", " ").upper()
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    session['logged_in'] = True
    session['username'] = username
    print(f"User {username} logged in successfully")
    flash('Vous vous êtes connecté avec succès avec Google.', 'success')
    return redirect(url_for('index'))

@app.route('/cinetpay', methods=['GET'])
@login_required
def cinetpay():
    if not current_user.is_authenticated:
        flash('Vous devez être connecté pour accéder à cette page.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(current_user.id)
    transaction_id = str(random.randint(100000000, 999999999))
    amount = session.get('total_price', 0)
    
    return render_template('cinetpay.html', 
                           cinetpay_apikey = os.getenv('CINETPAY_APIKEY', '16490420165f879ee4f1253.15350040'),
                           cinetpay_site_id = os.getenv('CINETPAY_SITE_ID', '5882516'),
                           transaction_id=transaction_id,
                           amount=amount,
                           customer_name=user.username,
                           customer_surname='',
                           customer_email=user.email,
                           customer_phone_number='',
                           customer_address='',
                           customer_city='',
                           customer_country='CM',
                           customer_state='',
                           customer_zip_code='')

@app.route('/cinetpay_notify', methods=['POST'])
def cinetpay_notify():
    data = request.json
    print(data)
    if data.get('status') == 'ACCEPTED':
        # Clear the cart after successful payment
        cart_items = session.pop('cart_items', [])
        session.pop('total_price', None)
        flash('Votre paiement a été effectué avec succès. Votre panier a été vidé.', 'success')
        
        # Process each item in the cart as a purchase
        purchased_items = []
        for item in cart_items:
            product_id = item['id']
            product = find_product_by_id(product_id)
            if product and product['codes']:
                used_code = product['codes'].pop(0)
                purchased_items.append({"name": product["name"], "code": used_code})
                if not product['codes']:
                    # Remove the product if no more codes are left
                    global products
                    products = [p for p in products if p['id'] != product_id]
                    flash(f'Achat réussi ! Votre code : {used_code}. Le produit {product["name"]} est maintenant en rupture de stock et a été retiré.', 'success')
                else:
                    flash(f'Achat réussi ! Votre code : {used_code} pour {product["name"]}', 'success')
            else:
                flash(f'Produit {product["name"]} non disponible ou en rupture de stock', 'danger')
        
        # Redirect to the purchase success page with the purchased items
        return render_template('purchase_success.html', purchased_items=purchased_items)
    else:
        flash('Votre paiement a échoué.', 'danger')
    return jsonify({'status': 'error', 'message': 'Échec du paiement'})

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html')



# Main entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("Starting Flask app")
    app.run(host='0.0.0.0', port=5000, debug=True)


