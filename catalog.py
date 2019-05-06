#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash)

from functools import wraps

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import cgi
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Categories, Base, CategoryItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import httplib2
import json
from flask import make_response
import requests
application = Flask(__name__)

engine = create_engine(
    'sqlite:///itemcatalog.db', connect_args={
        'check_same_thread': False
    })
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if login_session.get('username') is None:
            return redirect(url_for('showLogin', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@application.route('/test')
def testJSON():
    itemlist = session.query(CategoryItem)
    return jsonify(categories=[r.serialize for r in itemlist])


@application.route('/home/JSON')
def categoryJSON():
    categories = session.query(Categories)
    return jsonify(categories=[r.serialize for r in categories])


@application.route('/categories/<int:category_id>/itemlist/JSON')
def itemlistJSON(category_id):
    itemlist = session.query(CategoryItem).filter_by(category_id=category_id)
    return jsonify(itemlist=[r.serialize for r in itemlist])


@application.route('/topNewItem/JSON')
def topNewItemJSON():
    items = session.query(CategoryItem).order_by(
        CategoryItem.time_created.desc()).limit(10)
    return jsonify(itemlist=[r.serialize for r in items])


@application.route('/authorlist/JSON')
def authorlistJSON():
    authors = session.query(User)
    return jsonify(authors=[r.serialize for r in authors])


@application.route('/')
@application.route('/home')
def home():
    categories = session.query(Categories)
    return render_template('home.html', categories=categories)


@application.route('/topNewItem')
def topNewItem():
    items = session.query(CategoryItem).order_by(
        CategoryItem.time_created.desc()).limit(10)
    return render_template('topNewItem.html', items=items)


@application.route('/authorlist')
def authorlist():
    authors = session.query(User)
    return render_template('authorlist.html', authors=authors)


@application.route('/category/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCategory = Categories(
            name=request.form['name'],
            img=request.form['img'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('New Category Created', 'positive')
        return redirect(url_for('home'))
    else:
        return render_template('newCategory.html')


@application.route(
    '/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    category = session.query(Categories).filter_by(id=category_id).one()

    if request.method == 'POST':
        if category.user.name != login_session['username']:
            flash('Permission Edit! Unauthorised Edit!', 'Negative')
            return redirect(url_for('home'))

        category.name = request.form['name']
        category.img = request.form['img']
        session.add(category)
        session.commit()
        flash('Category Edited', 'positive')
        return redirect(url_for('home'))
    else:
        return render_template('editCategory.html', category=category)


@application.route(
    '/categories/<int:category_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    category = session.query(Categories).filter_by(id=category_id).one()

    if request.method == 'POST':
        if category.user.name != login_session['username']:
            flash('Permission Denied! Unauthorised Delete!', 'Negative')
            return redirect(url_for('home'))

        session.delete(category)
        session.commit()
        flash('Item Deleted', 'positive')
        return redirect(url_for('home'))
    else:
        return render_template('deleteCategory.html', category=category)


@application.route('/categories/<int:category_id>/itemlist')
def itemlist(category_id):
    itemlist = session.query(CategoryItem).filter_by(category_id=category_id)
    return render_template(
        'itemlist.html', itemlist=itemlist, category_id=category_id)

    # return "itemlist"


@application.route(
    '/categories/<int:category_id>/itemlist/new', methods=['GET', 'POST'])
@login_required
def newItemList(category_id):
    if request.method == 'POST':
        newItem = CategoryItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item Created', 'positive')
        return redirect(url_for('itemlist', category_id=category_id))
    else:
        return render_template('newItem.html', category_id=category_id)


@application.route(
    '/categories/<int:category_id>/itemlist/<int:item_id>/edit',
    methods=['GET', 'POST'])
@login_required
def editItemList(category_id, item_id):
    category = session.query(Categories).filter_by(id=category_id).one()
    item = session.query(CategoryItem).filter_by(
        category_id=category_id).filter_by(id=item_id).one()

    if request.method == 'POST':
        if item.user.name != login_session['username']:
            flash('Permission Edit! Unauthorised Edit!', 'Negative')
            return redirect(url_for('home'))

        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item Edited', 'positive')
        return redirect(url_for('itemlist', category_id=category_id))
    else:
        return render_template(
            'editItem.html', item=item, category_name=category.name)


@application.route(
    '/categories/<int:category_id>/itemlist/<int:item_id>/delete',
    methods=['GET', 'POST'])
@login_required
def deleteItemList(category_id, item_id):
    category = session.query(Categories).filter_by(id=category_id).one()
    item = session.query(CategoryItem).filter_by(
        category_id=category_id).filter_by(id=item_id).one()

    if request.method == 'POST':
        if item.user.name != login_session['username']:
            flash('Permission Denied! Unauthorised Delete!', 'Negative')
            return redirect(url_for('home'))

        session.delete(item)
        session.commit()
        flash('Item Deleted', 'positive')
        return redirect(url_for('itemlist', category_id=category_id))
    else:
        return render_template(
            'deleteItem.html', item=item, category_name=category.name)


@application.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=login_session['state'])

    # return "Login page"


@application.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code, now compatible with Python3

    request.get_data()
    code = request.data.decode('utf-8')
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if the access token is valid

    access_token = credentials.access_token
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token  # noqa
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if there was an error in the access token info, abort

    if result.get('error') is not None:
        response = make_response(json.dumps('error.'), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is for the intended user

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID does not match given user ID."), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use

    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data.get('name', '')
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # show login success

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; height: 150px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa
    flash('you are now logged in as %s' % login_session['username'],
          'positive')

    return output


# DISCONNECT - Revoke a current user's token and reset their login_session.


@application.route('/gdisconnect')
def gdisconnect():

    # Only disconnect a connected user.

    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.', 401))
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token

    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':

        # Reset the user's session

        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        flash('You have been logged out!', 'positive')
        response = make_response(redirect('/home'))

        # response = make_response(json.dumps('disconnected.'), 200)
        # response.headers['Content-Type'] = 'application/json'

        return response
    else:

        # For whatever reason, the given token was invalid

        response = make_response(
            json.dumps('Failed to revoke token for the given user. Result: %s '
                       % result), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@application.route('/fbconnect', methods=['POST'])
def fbconnect():

    # verify state from login page

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print 'access token received %s ' % access_token

    # Read json file for app_id and app_secret

    app_id = json.loads(open('fb_client_secrets.json',
                             'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json',
                                 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API

    userinfo_url = 'https://graph.facebook.com/v3.2/me'
    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v3.2/me?access_token=%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout

    login_session['access_token'] = token

    # Get user picture

    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']

    # see if user exists

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # show login success

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; height: 150px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa

    flash('Now logged in as %s' % login_session['username'])
    return output


@application.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']

    # The access token must me included to successfully logout

    access_token = login_session['access_token']

    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    # Reset the user's session

    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['facebook_id']
    del login_session['picture']
    del login_session['access_token']
    del login_session['user_id']
    flash('You have been logged out!', 'positive')

    # Redirect back to home

    response = make_response(redirect('/home'))
    return response


# User Helper Functions


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'],
        provider=login_session['provider'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


if __name__ == '__main__':
    application.secret_key = 'super_secret_key'
    application.debug = True
    application.run(host='0.0.0.0', port=5000)
