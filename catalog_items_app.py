import httplib2
import json
import random
import requests
import string

from flask import Flask, render_template, request, redirect, url_for, \
    flash, jsonify, session as login_session, make_response
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Restaurant, MenuItem

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenu.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

RESTAURANT_TEMPLATE = 'restaurants.html'
NEW_RESTAURANT_TEMPLATE = 'new_restaurant.html'
EDIT_RESTAURANT_TEMPLATE = 'edit_restaurant.html'
DELETE_RESTAURANT_CONFIRM_TEMPLATE = 'delete_restaurant_confirm.html'
MENU_TEMPLATE = 'menu.html'
NEW_MENU_ITEM_TEMPLATE = 'new_menu_item.html'
EDIT_MENU_ITEM_TEMPLATE = 'edit_menu_item.html'
DELETE_MENU_ITEM_CONFIRM_TEMPLATE = 'delete_menu_item_confirm.html'
LOGIN = 'login.html'
CLIENT_SECRET_JSON = 'client_secrets.json'
CLIENT_ID = json.loads(
    open(CLIENT_SECRET_JSON, 'r').read())['web']['client_id']


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template(LOGIN, STATE=state)


@app.route('/login_with_google', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
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
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    print(result)
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
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']


    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['email'])
    print("done!")
    return output


@app.route('/logout')
def logout():
    access_token = login_session.get('access_token')
    if access_token is None:
        return generate_response('Current user not connected.', 401)
    url = 'https://accounts.google.com/o/oauth2/revoke?token={0}' \
        .format(login_session['access_token'])
    http = httplib2.Http()
    result = http.request(url, 'GET')[0]
    if result['status'] != 200:
        return generate_response('Failed to revoke token for given user.', 400)
    remove_login_session_attributes()
    return generate_response('Successfully disconnected.', 200)


@app.route('/restaurants/JSON', methods=['GET'])
def retrieve_restaurants_json():
    restaurants = session.query(Restaurant).all()
    return jsonify(
        Restaurant=[restaurant.serialize for restaurant in restaurants])


@app.route('/')
@app.route('/restaurants', methods=['GET'])
def retrieve_restaurants():
    restaurants = session.query(Restaurant).all()
    return render_template(RESTAURANT_TEMPLATE, restaurants=restaurants)


@app.route('/restaurants/new', methods=['GET', 'POST'])
def create_restaurant():
    if request.method == 'POST':
        restaurant = configure_restaurant(request.form)
        add_or_edit_model(restaurant)
        generate_messages(restaurant.name, 'added')
        return redirect(url_for('retrieve_restaurants'))
    else:
        return render_template(NEW_RESTAURANT_TEMPLATE)


@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'])
def edit_restaurant(restaurant_id):
    restaurant = retrieve_restaurant(restaurant_id)
    if request.method == 'POST':
        if request.form['name']:
            restaurant.name = request.form['name']
            add_or_edit_model(restaurant)
            generate_messages(restaurant.name, 'edited')
        return redirect(
            url_for('retrieve_restaurants', restaurant_id=restaurant_id))
    return render_template(EDIT_RESTAURANT_TEMPLATE,
                           restaurant_id=restaurant_id, restaurant=restaurant)


@app.route('/restaurants/<restaurant_id>/delete', methods=['GET', 'POST'])
def delete_restaurant(restaurant_id):
    restaurant = retrieve_restaurant(restaurant_id)
    if request.method == 'POST':
        restaurant_name = restaurant.name
        delete_model(restaurant)
        generate_messages(restaurant_name, 'removed')
        return redirect(url_for('retrieve_restaurants'))
    return render_template(DELETE_RESTAURANT_CONFIRM_TEMPLATE,
                           restaurant_id=restaurant_id, restaurant=restaurant)


@app.route('/restaurants/<int:restaurant_id>/menu_itens', methods=['GET'])
def retrieve_menu_items(restaurant_id):
    restaurant = retrieve_restaurant(restaurant_id)
    items = session.query(MenuItem) \
        .filter_by(restaurant_id=restaurant_id) \
        .all()
    return render_template(MENU_TEMPLATE, restaurant=restaurant, items=items)


@app.route('/restaurants/<restaurant_id>/menu_itens/JSON', methods=['GET'])
def retrieve_menu_items_json(restaurant_id):
    items = session.query(Restaurant) \
        .filter_by(restaurant_id=restaurant_id) \
        .all()
    return jsonify(MenuItem=[item.serialize for item in items])


@app.route('/restaurants/<int:restaurant_id>/menu_items/new',
           methods=['GET', 'POST'])
def create_menu_item(restaurant_id):
    if request.method == 'POST':
        item = configure_menu_item(request.form, restaurant_id)
        add_or_edit_model(item)
        generate_messages(item.name, 'added')
        return redirect(url_for('retrieve_menu_items',
                                restaurant_id=restaurant_id))
    return render_template(NEW_MENU_ITEM_TEMPLATE,
                           restaurant_id=restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
def edit_menu_item(restaurant_id, item_id):
    item = retrieve_menu_item(item_id)
    if request.method == 'POST':
        item = validate_form_to_edit_item(item, request.form)
        add_or_edit_model(item)
        generate_messages(item.name, 'edited')
        return redirect(url_for('retrieve_menu_items',
                                restaurant_id=restaurant_id))
    return render_template(EDIT_MENU_ITEM_TEMPLATE,
                           restaurant_id=restaurant_id,
                           item_id=item_id, item=item)


@app.route('/restaurants/<restaurant_id>/<item_id>/delete',
           methods=['GET', 'POST'])
def delete_menu_item(restaurant_id, item_id):
    item = retrieve_menu_item(item_id)
    if request.method == 'POST':
        item_name = item.name
        delete_model(item)
        generate_messages(item_name, "removed")
        return redirect(url_for('retrieve_menu_items',
                                restaurant_id=restaurant_id))
    return render_template(DELETE_MENU_ITEM_CONFIRM_TEMPLATE,
                           restaurant_id=restaurant_id, item=item)


def configure_restaurant(form):
    return Restaurant(name=form['name'])


def configure_menu_item(form, restaurant_id):
    return MenuItem(name=form['name'],
                    description=form['description'],
                    price=form['price'],
                    course=form['course'],
                    restaurant_id=restaurant_id)


def validate_form_to_edit_item(item, form):
    if form['name']:
        item.name = form['name']
    if form['description']:
        item.description = form['description']
    if form['price']:
        item.price = form['price']
    if form['course']:
        item.course = form['course']
    return item


def add_or_edit_model(model):
    session.add(model)
    session.commit()


def delete_model(model):
    session.delete(model)
    session.commit()


def retrieve_restaurant(restaurant_id):
    return session.query(Restaurant).filter_by(id=restaurant_id).one()


def retrieve_menu_item(item_id):
    return session.query(MenuItem).filter_by(id=item_id).one()


def generate_messages(name, action):
    return flash("{} {} with success!".format(name, action))


def generate_response(message, status_http_code):
    response = make_response(json.dumps(message), status_http_code)
    response.headers['Content-Type'] = 'application/json'
    return response


def generate_json_params(credentials):
    return {
        'access_token': credentials.access_token,
        'alt': 'json'
    }


def generate_output():
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px;' \
              ' height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as {0}".format(login_session['email']))
    return output


def remove_login_session_attributes():
    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
