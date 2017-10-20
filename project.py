from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from sqlalchemy.orm.exc import NoResultFound
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json',  'r').read())['web']['client_id']

engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for later validation.


@app.route('/login')
def show_login():
    """Show the login screen to a user."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Performs app login via Google oauth."""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        # Upgrade the authorization one-time code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID doesn't match app's."), 401)
        print "Token's client ID doesn't match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in.
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the acces token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # Check if the user exists in the database. If not create a new user.
    user_id = get_user_id(login_session['email'])
    if user_id is None:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width: 300px; height: 300px; border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """Revoke a current user's token and reset their login session."""
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('''Current 
            user not connected.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token.
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Login via Facebook OAuth"""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data

    # Exchange client token for long-lived server-side token
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API.
    userinfo_url = "https://graph.facebook.com/v2.5/me"

    # Strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.5/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to proplerly
    # logout, let's strip out the information before the equals sign in
    # our token.
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = ('https://graph.facebook.com/v2.5/me/picture?%s&redirect=0'
           '&height=200&width=200') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # Check if the user exists in the database. If not create a new user.
    user_id = get_user_id(login_session['email'])
    if user_id is None:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width: 300px; height: 300px; border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """Logout via Facebook OAuth."""
    facebook_id = login_session['facebook_id']

    # The access token must be included to successfully logout.
    access_token = login_session['access_token']

    url = ('https://graph.facebook.com/%s/permissions?'
           'access_token=%s') % (facebook_id, access_token)
    print url
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out"


@app.route('/disconnect')
def disconnect():
    """Generic disconnect function that supports multiple OAuth providers."""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']

        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']

        flash("You have successfully been logged out.")
        return redirect(url_for('show_restaurants'))

    else:
        flash("You were not logged in to begin with!")
        return redirect(url_for('show_restaurants'))


@app.route('/')
@app.route('/restaurants/')
def show_restaurants():
    """Show all restaurants"""
    restaurants = session.query(Restaurant).all()
    if 'username' not in login_session:
        return render_template('public_restaurants.html',
                               restaurants=restaurants)
    else:
        return render_template('restaurants.html', restaurants=restaurants)


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def new_restaurant():
    """Create a new restaurant"""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_restaurant = Restaurant(name=request.form['name'],
                                    user_id=login_session['user_id'])
        session.add(new_restaurant)
        session.commit()
        flash("New Restaurant Created")
        return redirect(url_for('show_restaurants'))
    else:
        return render_template('new_restaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def edit_restaurant(restaurant_id):
    """Edit a restaurant"""
    if 'username' not in login_session:
        return redirect('/login')
    try:
        restaurant_to_edit = (session.query(Restaurant).
                              filter_by(id=restaurant_id).one())
    except:
        return "No restaurant exists with that ID."

    if login_session['user_id'] != restaurant_to_edit.user_id:
        flash("This is not your restaurant, so you can't edit it.")
        return redirect(url_for('show_restaurants'))

    if request.method == 'POST':
        if request.form['name']:
            restaurant_to_edit.name = request.form['name']
        session.add(restaurant_to_edit)
        session.commit()
        flash("Restaurant Successfully Edited")
        return redirect(url_for('show_restaurants'))
    else:
        return render_template('edit_restaurant.html',
                               restaurant=restaurant_to_edit)


@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def delete_restaurant(restaurant_id):
    """Delete a restaurant"""
    if 'username' not in login_session:
        return redirect('/login')
    try:
        restaurant_to_delete = (session.query(Restaurant).
                                filter_by(id=restaurant_id).one())
    except NoResultFound:
        return "No restaurant exists with that ID."

    if login_session['user_id'] != restaurant_to_delete.user_id:
        flash("This is not your restaurant, so you can't delete it.")
        return redirect(url_for('show_restaurants'))

    if request.method == 'POST':
        session.delete(restaurant_to_delete)
        session.commit()
        flash("Restaurant Successfully Deleted")
        return redirect(url_for('show_restaurants'))
    else:
        return render_template('delete_restaurant.html',
                               restaurant=restaurant_to_delete)


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def show_menu(restaurant_id):
    """Show a restaurant menu"""
    try:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    except NoResultFound:
        return "No restaurant exists with that ID." 

    creator = get_user_info(restaurant.user_id)
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()

    if ('username' not in login_session or
        login_session['user_id'] != restaurant.user_id):

        return render_template('public_menu.html',
                               restaurant=restaurant,
                               items=items,
                               creator=creator)
    else:
        return render_template('menu.html',
                               restaurant=restaurant,
                               items=items,
                               creator=creator)


@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET','POST'])
def new_menu_item(restaurant_id):
    """Create a new menu item"""
    if 'username' not in login_session:
        return redirect('/login')
    try:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    except NoResultFound:
        return "No restaurant exists with that ID." 

    if login_session['user_id'] != restaurant.user_id:
        flash("you can't create a new menu item.")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        new_item = MenuItem(name=request.form['name'],
                            description=request.form['description'],
                            price=request.form['price'],
                            course=request.form['course'],
                            restaurant_id=restaurant_id,
                            user_id=restaurant.user_id)
        session.add(new_item)
        session.commit()
        flash("New Menu Item Created")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))
    else:
        return render_template('new_menu_item.html', restaurant=restaurant)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit/',
           methods=['GET', 'POST'])
def edit_menu_item(restaurant_id, menu_id):
    """Edit a menu item"""
    if 'username' not in login_session:
        return redirect('/login')
    try:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    except NoResultFound:
        return "No restaurant exists with that ID." 
    try:
        item = session.query(MenuItem).filter_by(id=menu_id).one()
    except NoResultFound:
        return "No menu item exists with that ID."

    if login_session['user_id'] != restaurant.user_id:
        flash("This is not your restaurant, so you can't edit a menu item.")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        item.description = request.form['description']
        item.price = request.form['price']
        if request.form['course']:
            item.course = request.form['course']
        session.add(item)
        session.commit()
        flash("Menu Item Successfully Edited")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))
    else:
        return render_template('edit_menu_item.html',
                               restaurant=restaurant,
                               item=item)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete/',
           methods=['GET','POST'])
def delete_menu_item(restaurant_id, menu_id):
    """Delete a menu item"""
    if 'username' not in login_session:
        return redirect('/login')
    try:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    except NoResultFound:
        return "No restaurant exists with that ID." 
    try:
        item = session.query(MenuItem).filter_by(id=menu_id).one()
    except NoResultFound:
        return "No menu item exists with that ID."

    if login_session['user_id'] != restaurant.user_id:
        flash("This is not your restaurant, so you can't delete a new menu item.")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Menu Item Successfully Deleted")
        return redirect(url_for('show_menu', restaurant_id=restaurant_id))
    else:
        return render_template('delete_menu_item.html',
                               restaurant=restaurant,
                               item=item)


# Make JSON API endpoints for restaurants and menu items
@app.route('/restaurants/JSON/')
def restaurants_json():
    """Returns a JSON file containing the restaurants."""
    restaurants = session.query(Restaurant).all()
    return jsonify(Restaurants=[i.serialize for i in restaurants])


@app.route('/restaurants/<int:restaurant_id>/menu/JSON/')
def restaurant_menu_json(restaurant_id):
    """Returns a JSON file of menu items for a restaurant."""
    try:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    except:
        return "No restaurant exists with that ID."
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON/')
def restaurant_menu_item_json(restaurant_id, menu_id):
    """Returns a JSON file of a single menu item."""
    try:
        item = session.query(MenuItem).filter_by(id=menu_id).one()
    except:
        return "No menu item exists with that ID."
    return jsonify(MenuItem=item.serialize)


def create_user(login_session):
    """Create a new user in the database."""
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    """Get info for a user from the database."""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    """Given an email address, return the user ID, if in the database."""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key' 
    app.debug = True
    app.run(host='0.0.0.0', port=5000)