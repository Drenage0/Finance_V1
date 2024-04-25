import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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
    # check how much cash user has
    users_cash = db.execute("""
                    SELECT cash FROM users
                    WHERE id = ?""", session["user_id"]
                            )
    try:
        users_cash = round(users_cash[0]['cash'], 2)
    except:
        apology("Something went wrong", 400)

    # check users_stocks database
    stocks = db.execute("""
                    SELECT
                      symbol,
                      number_of_shares
                    FROM users_stocks
                    WHERE users_id = ?
                    ORDER BY symbol""", session["user_id"]
                        )

    try:
        stock['number_of_shares'] = int(stock['number_of_shares'])
    except:
        apology("Something went wrong", 400)

    # USER HAS stocks in users_stocks
    if stocks:
        total_value = 0.0
        for stock in stocks:
            current_price = lookup(stock['symbol'])
            # value of all stocks
            total_value += current_price['price'] * \
                int(stock['number_of_shares'])
            # current price of 1 stock
            stock['current_price'] = current_price['price']
            # price of all shares of 1 stock
            stock['shares_value'] = current_price['price'] * \
                int(stock['number_of_shares'])

        # total_value = round(total_value, 2)
        grand_total = total_value + users_cash
        return render_template("index.html", stocks=stocks, balance=usd(users_cash),  grand_total=usd(grand_total))
    # USER DOES NOT HAVE stocks in users_stocks
    total_value = 0.0
    grand_total = total_value + users_cash
    return render_template("index.html", stocks=stocks, balance=usd(users_cash), grand_total=usd(grand_total))
    # value of stocks + cash balance


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """POST METHOD"""
    if request.method == "POST":
        # check for valid symbol
        symbol = request.form.get("symbol").upper()
        if lookup(symbol) == None:
            return apology(f"'{symbol}' Stock name NOT found", 400)

        # check for valid shares input(int number > 0)
        shares = request.form.get("shares")
        try:
            shares = int(shares)
            if not shares > 0:
                return apology("Number of shares NOT valid", 400)
        except (ValueError, IndexError) as e:
            return apology("Number of shares NOT valid", 400)

        # check status with buy_shares function from helpers.py
        # inputs valid, can insert them in database
        # check how much cash user has
        users_cash = db.execute("""
                        SELECT cash FROM users
                        WHERE id = ?""", session["user_id"]
                                )
        # potential index error?
        if len(users_cash) > 0:
            # changing a list of dictionaries to single value!
            users_cash = users_cash[0]['cash']
        else:
            return apology("Something went wrong", 400)  # NOT OK

        # check how much purchasing given number of stocks cost and if user can afford it
        row = lookup(symbol)

        if row['price']*shares < users_cash:  # USER CAN AFFORD

            # add transaction into transaction_history database
            db.execute("""
                    INSERT INTO transaction_history
                        (users_id, symbol, type, number_of_shares, price_one, price_total)
                        VALUES (?, ?, "buy", ?, ?, ?)
                        """, session["user_id"], row['symbol'], shares, usd(row['price']), usd(row['price']*shares)
                       )
            # insert SUBSTRACTED cash amount into users database
            transaction_value = round(row['price']*shares, 2)
            updated_cash = round(users_cash - transaction_value, 2)
            db.execute("""
                    UPDATE users
                        SET cash = ?
                        WHERE id = ?""", updated_cash, session["user_id"]
                       )

            # insert information about bought stocks to users_stocks database
            # first check if user already has this stock in database
            stock_check = db.execute("""
                    SELECT * FROM users_stocks
                        WHERE users_id = ?
                        AND symbol = ?""", session["user_id"], row['symbol']
                                     )
            print(f"stock check = {stock_check}")

            if stock_check != []:  # THERE IS the stock in users_stocks - UPDATDE
                stock_check[0]['number_of_shares'] = int(
                    stock_check[0]['number_of_shares'])
                db.execute("""
                    UPDATE users_stocks
                        SET number_of_shares = ?
                        WHERE users_id = ?
                            AND symbol = ?""", stock_check[0]['number_of_shares'] + shares, session["user_id"], row['symbol']
                           )
            else:  # THERE IS NOT - INSERT
                db.execute("""
                    INSERT INTO users_stocks
                        (users_id, symbol, number_of_shares) VALUES
                        (?, ?, ?)""", session["user_id"], row['symbol'], shares
                           )
            # flash info about transaction
            flash(
                f"Bought {shares} of {symbol} for {usd(transaction_value)}, Updated cash: {usd(updated_cash)} ")
            return redirect("/")

        else:  # CANT AFFORD
            return apology(f"You can't afford to buy {shares} '{symbol}' shares!", 400)

    """GET METHOD"""
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    stocks = db.execute("""
                SELECT
                      symbol,
                      number_of_shares,
                      type,
                      price_one,
                      price_total,
                      timestamp_info
                FROM transaction_history
                      WHERE users_id = ?
                      ORDER BY timestamp_info DESC
                      """, session["user_id"]
                        )
    """Show history of transactions"""
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id - I think it would be better to have something like @cantbe_loggedin decorator
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

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

# //2 Now this - chyba done


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        row = lookup(request.form.get("symbol"))
        if row == None:
            print(f"{row}")
            return apology(f"stock symbol '{request.form.get('symbol')}' doesn't exist", 400)
        else:
            print(f"{row['price']}")
            return render_template("quoted.html", symbol=row["symbol"], price=row["price"])

    return render_template("quote.html")


# /// I think done
@app.route("/register", methods=["GET", "POST"])
def register():

    # Forget any user_id - I think it would be better to have something like @cantbe_loggedin decorator
    session.clear()

    """POST METHOD"""
    if request.method == "POST":
        # make sure username sent + checking if given username has spaces
        username = request.form.get("username")
        if not username:
            return apology("Must enter username", 400)

        for c in username:
            if c == " ":
                return apology("Username can't have spaces!", 400)

        # make sure password sent and if repeated password correct
        password = request.form.get("password")
        if not password:
            return apology("Password required", 400)

        if password != request.form.get("confirmation"):
            return apology("Passwords aren't the same!", 400)

        # check given username already in database
        check = db.execute("""
                   SELECT * FROM users
                   WHERE username = ?""", username)
        if check != []:
            return apology(f"Username '{username}' already exists. Try something else!", 400)

        # if username and password checked for errors
        # insert values into database using ? to avoid SQL attacks
        db.execute("""
                   INSERT INTO users
                   (username, hash) VALUES
                   (?, ?)""", username, generate_password_hash(password, method="scrypt")
                   )

        # finally accept session["user_id"] as an ID from database
        # first find id of given user, then assign to session
        user_id = db.execute("""
                   SELECT id FROM users
                   WHERE username = ?""", username
                             )
        print(f"user id = {user_id}")
        session["user_id"] = user_id[0]["id"]

        # last step redirect to main page
        flash("Registered!")
        return redirect("/")
    """GET METHOD"""
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # TODO: redirect to home
    """POST METHOD"""
    if request.method == "POST":
        # check for valid symbol - if the user has it in users_stocks database
        symbol = request.form.get("symbol")
        users_stocks = db.execute("""
                    SELECT symbol FROM users_stocks
                    WHERE users_id = ?""", session["user_id"]
                                  )
        if not len(users_stocks) > 0:
            return apology("something went wrong", 400)

        # check if there is symbol in users_stocks database
        # I'm using flag found here
        found = False
        for dictionary in users_stocks:
            if dictionary['symbol'] == symbol:
                found = True
                break
        if not found:
            return apology(f"You don't own '{symbol}' stock", 400)

        # check for valid shares input(int and int > 0)
        shares = request.form.get("shares")
        try:
            shares = int(shares)
            if not shares > 0:
                return apology("Number of shares NOT valid")
        except (ValueError, IndexError) as e:
            return apology("Number of shares NOT valid")

        # check users_stock database
        users_stocks = db.execute("""
                            SELECT number_of_shares FROM users_stocks
                                  WHERE users_id = ?
                                  AND symbol = ?
                                  """, session["user_id"], symbol
                                  )

        if not len(users_stocks) > 0:
            return apology("something went wrong", 400)

        # Users has MORE OR EQUAL stocks
        if users_stocks[0]['number_of_shares'] >= shares:
            print("You have more stocks than want to sell")

            # check how much for selling stock
            row = lookup(symbol)

            # add transaction into transaction_history database - TYPE SELL
            db.execute("""
                INSERT INTO transaction_history
                    (users_id, symbol, type, number_of_shares, price_one, price_total)
                    VALUES (?, ?, "sell", ?, ?, ?)
                    """, session["user_id"], row['symbol'], shares, usd(row['price']), usd(row['price']*shares)
                       )

            # check how much cash user has
            users_cash = db.execute("""
                            SELECT cash FROM users
                            WHERE id = ?""", session["user_id"]
                                    )
            # potential index error?
            if len(users_cash) > 0:
                # changing a list of dictionaries to single value!
                users_cash = round(users_cash[0]['cash'], 2)
            else:
                return apology("Something went wrong", 400)

            # insert ADDED cash amount into users database
            transaction_value = row['price']*shares
            updated_cash = users_cash + transaction_value

            db.execute("""
                UPDATE users
                    SET cash = ?
                    WHERE id = ?""", updated_cash, session["user_id"]
                       )

            stock_check = db.execute("""
                    SELECT * FROM users_stocks
                        WHERE users_id = ?
                        AND symbol = ?""", session["user_id"], row['symbol']
                                     )
            print(f"stock check = {stock_check}")

            # THERE IS - UPDATDE and wants to sell MAX
            if stock_check != [] and stock_check[0]['number_of_shares'] == shares:
                db.execute("""
                        DELETE FROM users_stocks
                            WHERE users_id = ?
                               AND symbol = ?
                                """, session["user_id"], row['symbol']
                           )

            # THERE IS - UPDATDE and wants to sell less than MAX
            elif stock_check != [] and stock_check[0]['number_of_shares'] != shares:
                db.execute("""
                        UPDATE users_stocks
                            SET number_of_shares = ?
                            WHERE users_id = ?
                                AND symbol = ?""", stock_check[0]['number_of_shares'] - shares, session["user_id"], row['symbol']
                           )
            else:  # THERE IS NOT - INSERT
                db.execute("""
                    INSERT INTO users_stocks
                        (users_id, symbol, number_of_shares) VALUES
                        (?, ?, ?)""", session["user_id"], row['symbol'], shares

                           )
            # flash info about transaction
            flash(
                f"Sold {shares} of {symbol} for {usd(transaction_value)}, Updated cash: {usd(updated_cash)} ")
            return redirect("/")

        else:  # Users DOES NOT have ENOUGH stocks
            print("I was here")
            return apology(f"You don't have {shares} '{symbol}' shares!")

    """GET METHOD"""

    # check users_stocks database
    symbols = db.execute("""
                    SELECT symbol
                    FROM users_stocks
                    WHERE users_id = ?""", session["user_id"]
                         )
    return render_template("sell.html",  symbols=symbols)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    # check how much cash user has
    users_cash = db.execute("""
                    SELECT cash FROM users
                    WHERE id = ?""", session["user_id"]
                            )
    # potential index error?
    if len(users_cash) > 0:
        # changing a list of dictionaries to single value!
        users_cash = round(users_cash[0]['cash'], 2)
    else:
        return apology("Something went wrong", 400)

    """POST METHOD"""
    if request.method == "POST":
        # check valid input amount
        users_amount = request.form.get("amount")
        try:
            users_amount = round(float(users_amount), 2)
        except ValueError:
            return apology("Invalid amount", 400)
        if not users_amount or users_amount < 10:
            return apology("Amount must be greater than $10.00", 400)
        # calculate updated cash
        updated_cash = round(users_cash + users_amount, 2)
        # add it to database
        db.execute("""
                UPDATE users
                SET cash = ?
                WHERE id = ?""", updated_cash, session["user_id"]
                   )
        flash(
            f"Succesfully added {usd(users_amount)} to cash balance now you have {usd(users_amount+users_cash)} ")
        return redirect("/")

    else:
        return render_template("add.html", cash=users_cash)
