from flask import Flask, render_template, redirect, url_for, request, session, flash, g
import sqlite3
import secrets
import time
import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(120)  # Generates a 240-character long hexadecimal string
app.config['DATABASE'] = 'FMS.db'

# SQLite3 database connection
conn = sqlite3.connect('FMS.db')
cursor = conn.cursor()


@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def home():
    return render_template('home.html', title="FMS Tracker")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        # Fetch user details including is_admin
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and user['password'] == password:
            # Set session variables
            session['username'] = username
            session['user_id'] = user['user_id']  # Set user_id in the session
            session['is_admin'] = user['is_admin']  # Set is_admin in the session

            # Redirect to dashboard with user_id to allow IDOR vulnerability
            return redirect(url_for('dashboard', user_id=user['user_id']))  # Redirecting to the user's dashboard
        else:
            flash('Invalid username or password. Please try again.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html', title="Login - FMS Tracker")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        userType = request.form['userType']

        db = get_db()
        cursor = db.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        # Insert the new user into the users table
        cursor.execute("INSERT INTO users (username, password, email, userType) VALUES (?, ?, ?, ?)",
                       (username, password, email, userType))
        db.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('signup.html', title="Sign Up - FMS Tracker")


@app.route('/dashboard/<int:user_id>')
def dashboard(user_id):
    if 'username' in session:
        username = session['username']
        # Use the user_id from the URL, which is now a parameter
        is_admin = session.get('is_admin', 0)  # Get is_admin status from the session, default to 0 if not found

        # Render the dashboard template with username and admin status
        return render_template('dashboard.html', title="User Dashboard", username=username, is_admin=is_admin, user_id=user_id)
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in


@app.route('/show_accounts')
def show_accounts():
    # Assuming you have a way to get the currently logged-in user's ID or username
    # Here, I'm assuming you retrieve it from the session
    current_user_id = session['user_id']

    # Query the database to get the accounts associated with the current user
    accounts = query_accounts_from_database(current_user_id)

    # Render the template and pass the accounts data to it
    return render_template('show_accounts.html', accounts=accounts)


@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    if 'username' not in session:
        flash('Please log in to create an account.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        account_name = request.form['account_name']
        account_type = request.form['account_type']
        current_balance = request.form['current_balance']

        db = get_db()
        cursor = db.cursor()

        # Generate a random account ID
        account_id = secrets.token_hex(16)

        # Check if the user already has an account of the same type
        cursor.execute("SELECT * FROM accounts WHERE user_id = ? AND accountType = ?", (user_id, account_type))
        existing_account = cursor.fetchone()
        if existing_account:
            flash(f'You already have a {account_type} account.', 'error')
            return redirect(url_for('accounts'))

        cursor.execute("INSERT INTO accounts (account_id, user_id, account_name, accountType, current_balance) "
                       "VALUES (?, ?, ?, ?, ?)",
                       (account_id, user_id, account_name, account_type, current_balance))
        db.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        return render_template('accounts.html', title="Create Account - FMS Tracker")


@app.route('/manage_users')
def manage_users():
    # Check if the user is logged in and is an admin
    if 'is_admin' not in session or session['is_admin'] != 1:
        flash("You do not have permission to access this page.", "warning")
        return redirect(url_for('dashboard'))  # Redirect to dashboard without user_id

    # Retrieve user_id from the session
    user_id = session.get('user_id')

    # Connect to the database
    db = get_db()
    cursor = db.cursor()

    # Fetch all users from the database
    cursor.execute("SELECT user_id, username, email, userType, is_admin FROM users")
    users = cursor.fetchall()

    # Render the manage_users template with the list of users and the user_id
    return render_template('manage_users.html', users=users, user_id=user_id)  # Pass user_id to template




@app.route('/manage_users/edit/<int:user_id>', methods=['GET'])
def edit_user(user_id):
    # Connect to the database
    conn = sqlite3.connect('FMS.db')
    cursor = conn.cursor()

    # Fetch user data from the database including user_id
    cursor.execute('SELECT user_id, username, email, userType, is_admin FROM users WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()  # Fetch the user data

    conn.close()

    if user:
        # Pass user data to the template for rendering
        return render_template('edit_user.html', user=user)  # No need for user_id here as it is already in user
    else:
        flash('User not found!', 'error')
        return redirect(url_for('manage_users'))  # Redirect back to manage users


@app.route('/manage_users/update/<int:user_id>', methods=['POST'])
def update_user(user_id):
    # Get updated data from the form
    username = request.form.get('username')
    email = request.form.get('email')
    userType = request.form.get('userType')
    is_admin = request.form.get('isAdmin')  # Get checkbox value
    is_admin = 1 if is_admin else 0  # Set to 1 if checked, otherwise 0

    try:
        # Connect to the database
        conn = sqlite3.connect('FMS.db')
        cursor = conn.cursor()

        # Update user data in the database
        cursor.execute('''
            UPDATE users
            SET username = ?, email = ?, userType = ?, is_admin = ?
            WHERE user_id = ?
        ''', (username, email, userType, is_admin, user_id))

        conn.commit()  # Commit the changes
        flash('User updated successfully!', 'success')  # Flash a success message
    except Exception as e:
        conn.rollback()  # Rollback changes on error
        flash(f'Error updating user: {str(e)}', 'error')  # Flash error message
    finally:
        conn.close()

    return redirect(url_for('manage_users'))  # Redirect back to manage users


@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    # Check if the user is logged in and is an admin
    if 'user_id' not in session or not session.get('is_admin', False):
        flash("Unauthorized access. Only admins can delete accounts.", 'error')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # Check if the user exists
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    if user:
        try:
            # Delete the user
            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            db.commit()
            flash("User deleted successfully.", 'success')
        except Exception as e:
            flash(f"An error occurred while deleting the user: {str(e)}", 'error')
            app.logger.error(f"Error deleting user {user_id}: {str(e)}")
    else:
        flash("User not found.", 'error')

    return redirect(url_for('manage_users'))  # Redirect to the user management page


@app.route('/user_accounts/<int:user_id>', methods=['GET'])
def user_accounts(user_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash("You need to log in first.", 'error')
        return redirect(url_for('login'))  # Redirect to login page if not logged in

    # Connect to the database
    db = get_db()
    cursor = db.cursor()

    # Query to get user details
    cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", 'error')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard if user not found

    # Query to get accounts associated with the user
    cursor.execute("SELECT name, balance FROM accounts WHERE user_id = ?", (user_id,))
    accounts = cursor.fetchall()

    db.close()  # Close the database connection

    # Render the accounts template with the user and accounts data
    return render_template('user_accounts.html', user=user, accounts=accounts)


@app.route('/viewUserAccounts/<int:user_id>')
def view_user_accounts(user_id):
    # Check if the user is logged in and is an admin
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('You must be an admin to view user accounts.', 'error')
        return redirect(url_for('login'))  # Redirect to the login page if not logged in or not an admin

    # Connect to the database
    cursor = get_db().cursor()

    try:
        # SQL query to fetch account_name and current_balance based on the specified user's ID
        cursor.execute("SELECT account_name, current_balance FROM accounts WHERE user_id = ?", (user_id,))
        accounts = cursor.fetchall()  # Fetch all accounts associated with the specified user ID

        # Check if any accounts are found
        if not accounts:
            flash('No accounts found for this user.', 'info')  # Inform the user if no accounts are found
    except Exception as e:
        flash('An error occurred while retrieving the accounts.', 'error')
        print("Database error:", e)  # Log the error for debugging
        return redirect(url_for('dashboard'))  # Redirect to a safe page on error
    finally:
        cursor.close()  # Ensure the cursor is closed whether the operation was successful or not

    # Render the accounts in the viewAccounts template
    return render_template('viewAccounts.html', accounts=accounts)  # Pass the retrieved accounts to the template


def is_admin(user_id):
    # Replace this with your actual logic to check if the user is an admin
    # For example, you could check a database or a hardcoded value
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        return result is not None and result[0]  # Assumes is_admin is a boolean
    except Exception as e:
        print("Error checking admin status:", e)
        return False
    finally:
        cursor.close()


@app.route('/create_account', methods=['POST'])
def create_account():
    if request.method == 'POST':
        # Retrieve form data
        account_type = request.form['accountType']
        current_balance = request.form['initialBalance']

        # Check user authentication
        if 'user_id' not in session:
            flash('User authentication error. Please log in again.', 'error')
            return redirect(url_for('dashboard'))

        try:
            # Retrieve username from session
            username = session.get('username')

            # Connect to the database
            db = get_db()
            cursor = db.cursor()

            # Insert new account into the accounts table
            cursor.execute("INSERT INTO accounts (user_id, username, account_name, accountType, current_balance) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (session['user_id'], username, f"{username}'s {account_type.capitalize()} "
                                                          f"Account", account_type, current_balance))
            db.commit()

            flash('New account created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error creating new account: {str(e)}', 'error')
            app.logger.error(f'Error creating new account: {str(e)}')
            return redirect(url_for('dashboard'))  # Redirect to dashboard on error


@app.route('/new_account_type', methods=['GET', 'POST'])
def new_account_type():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('User authentication error. Please log in again.', 'error')
        return redirect(url_for('dashboard'))

    # Now you can access the user_id directly from the session
    user_id = session['user_id']

    if request.method == 'POST':
        try:
            username = session.get('username')
            account_name = request.form['account_name']
            account_type = request.form['account_type']
            current_balance = request.form['current_balance']

            db = get_db()
            cursor = db.cursor()

            cursor.execute("INSERT INTO accounts (user_id, username, account_name, accountType, current_balance) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (user_id, username, account_name, account_type, current_balance))  # Use user_id from session
            db.commit()

            flash('New account type created successfully!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        except Exception as e:
            flash(f'Error creating new account: {str(e)}', 'error')
            app.logger.error(f'Error creating new account: {str(e)}')
            return redirect(url_for('dashboard'))  # Redirect to dashboard on error

    # Handle GET request method
    return render_template('NewAccountType.html', title="Create New Account Type")



@app.route('/logout')
def logout():
    # Clear the session (log out the user)
    session.pop('username', None)
    return redirect(url_for('home'))


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'FMS.db', None)
    if db is not None:
        db.close()


@app.route('/view_accounts/<int:user_id>')
def view_accounts(user_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('Please log in to view your accounts.', 'error')
        return redirect(url_for('login'))

    # You can choose to validate that the current user is accessing their own data
    current_user_id = session['user_id']

    # Fetch accounts using the user_id from the URL, this can lead to IDOR if not controlled properly
    accounts = query_accounts_from_database(user_id)

    return render_template('showaccounts.html', accounts=accounts, user_id=user_id)


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    error = None  # Define an error message variable
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if user is not logged in

    if request.method == 'GET':
        return render_template('transfer.html', error=error)  # Pass error message to template
    elif request.method == 'POST':
        # Retrieve form data
        sender_username = session['username']
        sender_account_id = int(request.form['sender_account_id'])
        recipient_account_id = int(request.form['recipient_account_id'])
        amount = float(request.form['amount'])

        # Check if sender's username is valid
        conn = sqlite3.connect('FMS.db')
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (sender_username,))
        user_id = cursor.fetchone()

        # Check if sender's account exists
        sender_account = get_account_details(sender_account_id)

        # Check if recipient's account exists
        recipient_account = get_account_details(recipient_account_id)

        conn.close()

        if user_id:
            # Check if the sender's user ID matches the account's user ID (authorization check)
            if sender_account and sender_account[1] == user_id[0]:
                # Check if both sender's and recipient's accounts exist
                if sender_account and recipient_account:
                    # Perform money transfer
                    if transfer_money(sender_account_id, recipient_account_id, amount):
                        # Add transaction record to the database
                        description = f"Transfer from account {sender_account_id} to account {recipient_account_id}"
                        add_transaction(sender_account_id, recipient_account_id, amount, description)

                        # Introduce a delay before redirecting
                        time.sleep(5)
                        return redirect(url_for('dashboard'))  # Redirect to dashboard after 5 seconds
                    else:
                        error = "Insufficient balance in the sender's account."  # Set error message
                else:
                    error = "Invalid sender or recipient account."  # Set error message
            else:
                error = "Invalid account or unauthorized access."  # Set error message
        else:
            error = "Invalid username."  # Set error message

        return render_template('transfer.html', error=error)


# Functions go here

def get_db():
    db = getattr(g, 'FMS.db', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db


def add_transaction(sender_account_id, recipient_account_id, amount, description):
    conn = sqlite3.connect('FMS.db')
    cursor = conn.cursor()

    try:
        # Get current datetime
        transact_datetime = datetime.datetime.now()

        # Fetch sender_username
        cursor.execute("SELECT username FROM accounts WHERE account_id = ?", (sender_account_id,))
        sender_username = cursor.fetchone()[0]

        # Fetch receiver_username
        cursor.execute("SELECT username FROM accounts WHERE account_id = ?", (recipient_account_id,))
        receiver_username = cursor.fetchone()[0]

        # Insert transaction record into transactions table
        cursor.execute("INSERT INTO transactions (sender_id, receiver_id, sender_username, receiver_username, "
                       "amount, transact_datetime, description) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (sender_account_id, recipient_account_id, sender_username, receiver_username, amount,
                        transact_datetime, description))
        conn.commit()
        print('Transaction added successfully!')
    except Exception as e:
        print(f'Error adding transaction: {str(e)}')
    finally:
        conn.close()


def get_account_details(account_id):
    conn = sqlite3.connect('FMS.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
    account = cursor.fetchone()
    conn.close()
    return account


# Function to transfer money between accounts
def transfer_money(sender_account_id, recipient_account_id, amount):
    conn = sqlite3.connect('FMS.db')
    cursor = conn.cursor()

    # Get sender's and recipient's account details
    sender_account = get_account_details(sender_account_id)
    recipient_account = get_account_details(recipient_account_id)

    # Check if sender's account exists and has enough balance
    if sender_account and sender_account[5] >= amount:
        # Deduct amount from sender's balance
        new_sender_balance = sender_account[5] - amount
        cursor.execute("UPDATE accounts SET current_balance = ? WHERE account_id = ?", (new_sender_balance, sender_account_id))

        # Add amount to recipient's balance
        new_recipient_balance = recipient_account[5] + amount
        cursor.execute("UPDATE accounts SET current_balance = ? WHERE account_id = ?", (new_recipient_balance, recipient_account_id))

        conn.commit()
        conn.close()
        return True
    else:
        conn.close()
        return False


def query_accounts_from_database(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,))
    return cursor.fetchall()


def update_sender_balance(account_id, new_balance):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE accounts SET current_balance = ? WHERE account_id = ?", (new_balance, account_id))
    db.commit()


def update_recipient_balance(account_id, new_balance):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE accounts SET current_balance = ? WHERE account_id = ?", (new_balance, account_id))
    db.commit()


def get_account_by_id(account_id, user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM accounts WHERE account_id = ? AND user_id = ?", (account_id, user_id))
    return cursor.fetchone()


if __name__ == '__main__':
    app.run(debug=True, port=27095, host='0.0.0.0')

    # Add Indexes - completed
    # add password hashing and maybe salting - Not done - tried - almost lost the project
    # add MAYBE user authentication - Not done - advanced goal
    # add input validation and other forms of data validation - Not done
    # Add indexes to the accounts table for the user_id and accountType columns to improve query performance. - Done
    # Run the following SQL commands in the SQLite shell to add the indexes:
    # CREATE INDEX idx_user_id ON accounts (user_id); - Done
    # CREATE INDEX idx_accountType ON accounts (accountType); - Done
    # You can also add indexes to other columns if needed.
    # To view the indexes in the database, run the following command:
    # .indexes accounts
