import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    id = session["user_id"]
    users_info = db.execute("SELECT username, cash FROM users WHERE id = ?", id)
    purchases = db.execute("SELECT stock, quantity FROM users_status WHERE user_id = ?", id)

    price = []
    total_value = 0
    for purchase in purchases:
        price.append(lookup(purchase.get("stock"))["price"])
        total_value += purchase.get("quantity") * price[-1]

    return render_template("index.html", user=users_info[0]["username"], cash=users_info[0]["cash"], purchases=purchases, total_value=total_value, price=price, lookup=lookup)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        id = session["user_id"]
        user_money = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

        if not symbol:
            return apology("Please enter a symbol", 403)

        if not shares:
            return apology("Please enter a number", 403)

        try:
            price = lookup(symbol)["price"]
        except TypeError:
            return apology("Not a valid symbol", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("Please enter a whole number")

        if shares <= 0:
            return apology("Please enter a positive number")

        if user_money < price * shares:
            return apology("Insufficient funds")

        user_money -= price * shares

        db.execute("INSERT INTO transactions (stock, quantity, price, time, type, user_id) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'buy', ?)", symbol, shares, price, id)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_money, id)

        if db.execute("SELECT * FROM users_status WHERE user_id = ? AND stock = ?", id, symbol) == []:
            db.execute(
                "INSERT INTO users_status (user_id, stock, quantity) VALUES (?, ?, ?)", id, symbol, shares)
        else:
            new_shares = shares + \
                db.execute("SELECT quantity FROM users_status WHERE stock = ?", symbol)[
                    0]["quantity"]
            db.execute("UPDATE users_status SET quantity = ? WHERE stock = ?", new_shares, symbol)
        flash("Successful purchase")

        return redirect("/")

    symbol = request.args.get('symbol', '')
    return render_template("buy.html", symbol=symbol)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session["user_id"]
    username = db.execute("SELECT username, cash FROM users WHERE id = ?", id)[0]["username"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", id)

    return render_template("history.html", user=username, transactions=transactions, lookup=lookup)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if 'stocks' not in session:
        session['stocks'] = []

    if request.method == 'POST':
        symbol = request.form.get('symbol')

        if not symbol:
            flash('Missing symbol')
            return apology("Missing symbol", 400)

        stock = lookup(symbol)

        if stock:
            session['stocks'].append(stock)
        else:
            flash('not a valid symbol')
            return apology("not a valid symbol", 400)

        return render_template('quoted.html', stocks=session["stocks"])

    if session['stocks']:
        return render_template('quoted.html', stocks=session["stocks"])

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmation')

        if not username or username.isspace():
            return apology('Must provide username', 400)
        if not password or password.isspace():
            return apology('Must provide password', 400)
        if not confirm_password:
            return apology('Must confirm password', 400)
        if password != confirm_password:
            return apology('password and confirmation do not match', 400)

        hashed_password = generate_password_hash(password)

        try:
            db.execute('INSERT INTO users (username, hash) VALUES (?, ?)',
                       username, hashed_password)
        except ValueError:
            return apology('This username already exist', 400)

        flash("Register successful")
        return redirect('/login')

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    id = session["user_id"]
    purchases = db.execute("SELECT stock, quantity FROM users_status WHERE user_id = ?", id)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        price = lookup(symbol)["price"]
        user_money = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Please enter a whole number", 400)

        user_money += price * shares
        user_shares = next((purchase["quantity"]
                           for purchase in purchases if purchase["stock"] == symbol), 0)

        if not symbol or symbol == "Choose a symbol":
            return apology("Please enter a symbol", 400)

        if not any(purchase['stock'] == symbol for purchase in purchases):
            return apology("Bad Request", 400)

        if not shares or shares <= 0:
            return apology("Please enter a positive number", 400)

        if shares > user_shares:
            return apology("You are trying to sell more shares than owned", 400)

        db.execute("INSERT INTO transactions (stock, quantity, price, time, type, user_id) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'sell', ?)", symbol, shares, price, id)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_money, id)

        if (user_shares - shares) == 0:
            db.execute("DELETE FROM users_status WHERE stock = ? AND user_id = ?", symbol, id)
        else:
            new_shares = user_shares - shares
            db.execute(
                "UPDATE users_status SET quantity = ? WHERE stock = ? AND user_id = ?", new_shares, symbol, id)
        flash("Sold successfuly")

        return redirect("/")

    symbol = request.args.get("symbol", "")
    return render_template("sell.html", purchases=purchases, symbol=symbol)


@app.route('/remove_stock', methods=["POST"])
def clear():
    symbol = request.form.get('symbol')
    for stock in session["stocks"]:
        if stock["symbol"] == symbol:
            session["stocks"].remove(stock)
            break

    return '', 204
