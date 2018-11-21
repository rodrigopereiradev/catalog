import catalog_controller as controller

from flask import Flask

'''
    This file is responsible recieve the requistions and send the response;
'''

app = Flask(__name__)


@app.route('/login')
def login():
    return controller.login();


@app.route('/login_with_google', methods=['POST'])
def gconnect():
    return controller.connect_with_google()


@app.route('/logout')
def logout():
    return controller.logout()


@app.route('/restaurants/JSON', methods=['GET'])
def retrieve_restaurants_json():
    return controller.retrieve_restaurants_json()


@app.route('/')
@app.route('/restaurants', methods=['GET'])
def retrieve_restaurants():
    return controller.retrieve_restaurants()


@app.route('/restaurants/new', methods=['GET', 'POST'])
def create_restaurant():
    return controller.create_restaurant()


@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'])
def edit_restaurant(restaurant_id):
    return controller.edit_restaurant(restaurant_id)


@app.route('/restaurants/<restaurant_id>/delete', methods=['GET', 'POST'])
def delete_restaurant(restaurant_id):
    return controller.delete_restaurant(restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/menu_itens', methods=['GET'])
def retrieve_menu_items(restaurant_id):
    return controller.retrieve_menu_items(restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/menu_itens/JSON', methods=['GET'])
def retrieve_menu_items_json(restaurant_id):
    return controller.retrieve_menu_items_json(restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/menu_items/new',
           methods=['GET', 'POST'])
def create_menu_item(restaurant_id):
    return controller.create_menu_item(restaurant_id)


@app.route('/restaurants/<int:item_id>/menu_item/JSON',
           methods=['GET', 'POST'])
def retrieve_menu_item_json(item_id):
    return controller.retrieve_menu_item_json(item_id)


@app.route('/restaurants/<int:restaurant_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
def edit_menu_item(restaurant_id, item_id):
    return controller.edit_menu_item(restaurant_id, item_id)


@app.route('/restaurants/<restaurant_id>/<item_id>/delete',
           methods=['GET', 'POST'])
def delete_menu_item(restaurant_id, item_id):
    return controller.delete_menu_item(restaurant_id, item_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
