from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, make_response
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

from datetime import date
import time


app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
GROUPS = "groups"
POSTS = "posts"
COMMENTS = "comments"

CLIENT_ID = 'lS6gVZBkMZzyn24f1ug5W4iC8n7Xrux3'
CLIENT_SECRET = 'MXg_lEyQb1lxzuoL0g_2pxhS6OX0wiFk8tqya6E7bVu51rixWETqRIVOw_fq8-ej'
DOMAIN = 'cs493-suhs.us.auth0.com'

CALLBACK_URL = 'https://final-suhs.appspot.com/callback'

ALGORITHMS = ["RS256"]


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):

    auth_header = request.headers['Authorization'].split()
    token = auth_header[1]

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False

        return payload
    else:
        return False


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/')
        return f(*args, **kwargs)

    return decorated


@app.route('/')
def home():
    return render_template('home.html')

# ------------------------------- DATABASE FUNCTIONALITY ----------------------------------------------- #

# ----- USERS ----- #


@app.route('/users', methods=['GET'])
def users_get():

    if request.method == 'GET':

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        query = client.query(kind=USERS)
        results = list(query.fetch())
        return (json.dumps(results), 200)


@app.route('/users/<id>', methods=['DELETE'])
def users_delete(id):

    if request.method == 'DELETE':

        # Get users of given id
        user_key = client.key(USERS, id)

        # Delete user
        client.delete(user_key)

        return ('', 204)

# ----- GROUPS ----- #


@app.route('/groups', methods=['GET', 'POST', 'PUT', 'DELETE'])
def groups_create_get():

    if request.method == 'GET':

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        query = client.query(kind=GROUPS)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + "groups/" + str(e.key.id)

            for f in e["posts"]:
                f["self"] = request.url_root + "posts/" + str(f["id"])

        output = {"total_groups": len(list(query.fetch()))}
        output["groups"] = results
        if next_url:
            output["next"] = next_url

        return (json.dumps(output), 200)

    elif request.method == 'POST':

         # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        content = request.get_json()
        new_group = datastore.entity.Entity(key=client.key(GROUPS))
        new_group.update({"name": content["name"], "description": content["description"], "posts": [
        ], "create_date": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})
        client.put(new_group)

        # Get the id of new group
        new_group_id = str(new_group.key.id)

        # Return group appropriately
        return_group = {"id": new_group_id, "name": new_group["name"],
                        "description": new_group["description"], "create_date": new_group["create_date"], "posts": new_group["posts"], "self": request.url_root + "groups/" + new_group_id}

        # Make response, headers, status code
        res = make_response(json.dumps(return_group))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res

    # 405 Error if PUT or DELETE
    elif request.method == 'PUT':
        return ({"Error": "You cannot edit the entire list of groups"}, 405)

    elif request.method == 'DELETE':
        return ({"Error": "You cannot delete the entire list of groups"}, 405)


@app.route('/groups/<id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def groups_get_delete_edit(id):

    if request.method == 'GET':

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get group for given id
        group_key = client.key(GROUPS, int(id))
        group = client.get(key=group_key)

        # If no group, error
        if not group:
            return ({"Error": "No group with this group_id exists"}, 404)

        for e in group["posts"]:
            e["self"] = request.url_root + "posts/" + str(e["id"])

        # Return group appropriately
        return_group = {"id": id, "name": group["name"],
                        "description": group["description"], "create_date": group["create_date"], "posts": group["posts"], "self": request.url_root + "groups/" + id}

                        
        res = make_response(json.dumps(return_group))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res

    elif request.method == 'DELETE':

        # Get group of given id
        group_key = client.key(GROUPS, int(id))
        group = client.get(key=group_key)

        if not group:
            return ({"Error": "No group with this group_id exists"}, 404)

        # Check all the posts in group (will not be deleted but have empty group now)
        for post in group['posts']:
            post_key = client.key(POSTS, post['id'])
            each_post = client.get(key=post_key)
            each_post['group'] = None
            client.put(each_post)

        # Delete group
        client.delete(group_key)

        return ('', 204)

    # Edit all attributes of group
    elif request.method == 'PUT':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # Check for all required attributes
        if "name" not in content or "description" not in content:
            return ({"Error": "The request object is missing at least one of the required attributes"}, 400)

        # Get group
        group_key = client.key(GROUPS, int(id))
        group = client.get(key=group_key)

        # Check if group of id exists
        if not group:
            return ({"Error": "No group with this group_id exists"}, 404)

        # Update group contents
        group.update(
            {"name": content["name"], "description": content["description"]})
        client.put(group)
        return_group = {"id": id, "name": group["name"],
                        "description": group["description"], "create_date": group["create_date"], "posts": group["posts"], "self": request.url_root + "groups/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_group))
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Location', return_group["self"])
        res.status_code = 303
        return res

    elif request.method == 'PATCH':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # If no attribute is given, error
        if "name" not in content and "description" not in content:
            return ({"Error": "No attribute was given"}, 400)

        # Get group
        group_key = client.key(GROUPS, int(id))
        group = client.get(key=group_key)

        # Check if group of id exists
        if not group:
            return ({"Error": "No group with this group_id exists"}, 404)

        # Update group contents
        if "name" in content:
            group.update({"name": content["name"]})
        if "description" in content:
            group.update({"description": content["description"]})

        client.put(group)

        return_group = {"id": id, "name": group["name"],
                        "description": group["description"], "create_date": group["create_date"], "posts": group["posts"], "self": request.url_root + "groups/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_group))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res


@app.route('/groups/<group_id>/posts/<post_id>', methods=['PUT', 'DELETE'])
def add_delete_group_to_post(group_id, post_id):

    # Check for missing access token
    if 'Authorization' not in request.headers:
        return ({"Error": "Missing JWT"}, 401)

    # Check for invalid access token
    if verify_jwt(request) is False:
        return ({"Error": "Invalid JWT"}, 401)

    payload = verify_jwt(request)

    group_key = client.key(GROUPS, int(group_id))
    group = client.get(key=group_key)
    post_key = client.key(POSTS, int(post_id))
    post = client.get(key=post_key)

    if not group and not post:
        return ({"Error": "The specified group and post does not exist"}, 404)
    if not group:
        return ({"Error": "The specified group does not exist"}, 404)
    if not post:
        return ({"Error": "The specified post does not exist"}, 404)

    # If no post with id, error
    if not post:
        return ({"Error": "No post with this post_id exists"}, 403)

    if post["author"] != payload["sub"]:
        return ({"Error": "Post is owned by someone else"}, 403)

    if request.method == 'PUT':

        if post['group'] is not None:
            return ({"Error": "The post is already assigned to a group"}, 403)

        group['posts'].append(
            {"id": post.id})
        post['group'] = group.id
        post['last_modified'] = date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")
        client.put(group)
        client.put(post)
        return('', 204)

    elif request.method == 'DELETE':

        found = 0
        for i in range(len(group['posts'])):
            if group['posts'][i]['id'] == int(post_id):
                found += 1
                del group['posts'][i]
                post['group'] = None
                client.put(group)
                client.put(post)
                return('', 204)

        if found == 0:
            return({"Error": "Post not in this group"}, 403)


# ----- POSTS ----- #


@app.route('/posts', methods=['GET', 'POST', 'PUT', 'DELETE'])
def posts_get_post():

    if request.method == 'GET':

        # Check for missing access token
        if 'Authorization' not in request.headers:
            return ({"Error": "Missing JWT"}, 401)

        if verify_jwt(request) is False:
            return ({"Error": "Invalid JWT"}, 401)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Verify JWT
        payload = verify_jwt(request)

        return_posts = []

        # Search all posts
        query = client.query(kind=POSTS)
        posts = list(query.fetch())

        # Only owner match
        for post in posts:
            if post["author"] == payload["sub"]:
                post["id"] = post.key.id
                post["self"] = request.url_root + \
                    "posts/" + str(post.key.id)

                for e in post["comments"]:
                    e["self"] = request.url_root + \
                        "comments/" + str(e["id"])

                return_posts.append(post)

        # Pagination
        return_posts = sorted(
            return_posts, key=lambda a: a["creation_date"], reverse=True)

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))

        return_posts_pagination = return_posts[q_offset:q_offset+q_limit]
        output = {"total_posts": len(return_posts)}
        output["posts"] = return_posts_pagination

        if q_limit+q_offset < len(return_posts):
            next_offset = q_offset + q_limit
            output["next"] = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)

        return (json.dumps(output), 200)

    elif request.method == 'POST':

        # Check for missing access token
        if 'Authorization' not in request.headers:
            return ({"Error": "Missing JWT"}, 401)

        if verify_jwt(request) is False:
            return ({"Error": "Invalid JWT"}, 401)

         # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Verify JWT
        payload = verify_jwt(request)

        content = request.get_json()
        new_post = datastore.entity.Entity(key=client.key(POSTS))
        new_post.update({"group": None, "author": payload["sub"], "title": content["title"],
                         "body": content["body"], "creation_date": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S"), "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S"), "comments": []})
        client.put(new_post)

        # Get the id of new post
        new_post_id = str(new_post.key.id)

        # Return post appropriately
        return_post = {"id": new_post_id, "group": new_post["group"],
                       "author": new_post["author"], "title": new_post["title"], "body": new_post["body"], "creation_date": new_post["creation_date"], "last_modified": new_post["last_modified"], "comments": new_post["comments"], "self": request.url_root + "posts/" + new_post_id}

        # Make response, headers, status code
        res = make_response(json.dumps(return_post))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res

    # 405 Error if PUT or DELETE
    elif request.method == 'PUT':
        return ({"Error": "You cannot edit the entire list of posts"}, 405)

    elif request.method == 'DELETE':
        return ({"Error": "You cannot delete the entire list of posts"}, 405)


@app.route('/posts/<id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def posts_get_delete_edit(id):

    if 'Authorization' not in request.headers:
        return ({"Error": "Missing JWT"}, 401)

    if verify_jwt(request) is False:
        return ({"Error": "Invalid JWT"}, 401)

    payload = verify_jwt(request)

    if request.method == 'GET':

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get post for given id
        post_key = client.key(POSTS, int(id))
        post = client.get(key=post_key)
        
        # If no post with id, error
        if not post:
            return ({"Error": "No post with this post_id exists"}, 403)

        # check if post author matches jwt
        if post["author"] != payload["sub"]:
            return ({"Error": "Post is owned by someone else"}, 403)

        for e in post["comments"]:
            e["self"] = request.url_root + \
                "comments/" + str(e["id"])

        # Return post appropriately
        return_post = {"id": id, "group": post["group"],
                       "author": post["author"], "title": post["title"], "body": post["body"], "creation_date": post["creation_date"], "last_modified": post["last_modified"], "comments": post["comments"], "self": request.url_root + "posts/" + id}

        res = make_response(json.dumps(return_post))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res

    # Delete a Post
    if request.method == 'DELETE':

        payload = verify_jwt(request)

        # Get post of given id
        post_key = client.key(POSTS, int(id))
        post = client.get(key=post_key)

        # If no post with id, error
        if not post:
            return ({"Error": "No post with this post_id exists"}, 403)

        if post["author"] != payload["sub"]:
            return ({"Error": "Post is owned by someone else"}, 403)

        # Delete all comments in post
        for comment in post['comments']:
            comment_key = client.key(COMMENTS, int(comment['id']))
            client.delete(comment_key)

        # Delete post
        client.delete(post_key)
        return ('', 204)

    # Edit all attributes of post
    elif request.method == 'PUT':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # Check for all required attributes
        if "title" not in content or "body" not in content:
            return ({"Error": "The request object is missing at least one of the required attributes"}, 400)

        # Get post
        post_key = client.key(POSTS, int(id))
        post = client.get(key=post_key)

        # Check if post of id exists
        if not post:
            return ({"Error": "No post with this post_id exists"}, 403)

        if post["author"] != payload["sub"]:
            return ({"Error": "Post is owned by someone else"}, 403)

        # Update post contents
        post.update(
            {"title": content["title"], "body": content["body"], "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})
        client.put(post)
        return_post = {"id": id, "group": post["group"],
                       "author": post["author"], "title": post["title"], "body": post["body"], "creation_date": post["creation_date"], "last_modified": post["last_modified"], "comments": post["comments"], "self": request.url_root + "posts/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_post))
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Location', return_post["self"])
        res.status_code = 303
        return res

    elif request.method == 'PATCH':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # If no attribute is given, error
        if "title" not in content and "body" not in content:
            return ({"Error": "No attribute was given"}, 400)

        # Get post
        post_key = client.key(POSTS, int(id))
        post = client.get(key=post_key)

        # Check if post of id exists
        if not post:
            return ({"Error": "No post with this post_id exists"}, 403)

        if post["author"] != payload["sub"]:
            return ({"Error": "Post is owned by someone else"}, 403)

        # Update post contents
        if "title" in content:
            post.update(
                {"title": content["title"], "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})
        if "body" in content:
            post.update(
                {"body": content["body"], "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})

        client.put(post)

        return_post = {"id": id, "group": post["group"],
                       "author": post["author"], "title": post["title"], "body": post["body"], "creation_date": post["creation_date"], "last_modified": post["last_modified"], "comments": post["comments"], "self": request.url_root + "posts/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_post))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res

    else:
        return jsonify(error='Method not recogonized')

# ----- COMMENTS ----- #


@app.route('/comments', methods=['GET', 'PUT', 'DELETE'])
def comments_get():

    if request.method == 'GET':

        # Check for missing access token
        if 'Authorization' not in request.headers:
            return ({"Error": "Missing JWT"}, 401)

        # Check for invalid access token
        if verify_jwt(request) is False:
            return ({"Error": "Invalid JWT"}, 401)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Verify JWT
        payload = verify_jwt(request)

        return_comments = []

        # Search all comments
        query = client.query(kind=COMMENTS)
        comments = list(query.fetch())

        # Only owner match
        for comment in comments:
            if comment["author"] == payload["sub"]:
                comment["id"] = comment.key.id
                comment["self"] = request.url_root + \
                    "comments/" + str(comment.key.id)

                return_comments.append(comment)

        # Pagination
        return_comments = sorted(
            return_comments, key=lambda a: a["creation_date"], reverse=True)

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))

        return_comments_pagination = return_comments[q_offset:q_offset+q_limit]
        output = {"total_comments": len(return_comments)}
        output["comments"] = return_comments_pagination

        if q_limit+q_offset < len(return_comments):
            next_offset = q_offset + q_limit
            output["next"] = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)

        return (json.dumps(output), 200)

    # 405 Error if PUT or DELETE
    elif request.method == 'PUT':
        return ({"Error": "You cannot edit the entire list of comments"}, 405)

    elif request.method == 'DELETE':
        return ({"Error": "You cannot delete the entire list of comments"}, 405)


@app.route('/posts/<id>/comments', methods=['POST'])
def comments_post(id):

    # Write a Comment on a specific post
    if request.method == 'POST':

        if 'Authorization' not in request.headers:
            return ({"Error": "Missing JWT"}, 401)

        if verify_jwt(request) is False:
            return ({"Error": "Invalid JWT"}, 401)

         # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        payload = verify_jwt(request)

        # Get Content of request and create a new comment
        content = request.get_json()
        new_comment = datastore.entity.Entity(key=client.key(COMMENTS))
        new_comment.update({"author": payload["sub"], "body": content["body"], "creation_date": date.today(
        ).strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S"), "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S"), "post_id": id})
        client.put(new_comment)

        # Get the id of new comment
        new_comment_id = str(new_comment.key.id)

        # Add comment to post
        post_key = client.key(POSTS, int(id))
        post = client.get(key=post_key)
        post['comments'].append(
            {"id": new_comment_id})

        client.put(post)

        # Return comment appropriately
        return_comment = {"id": new_comment_id, "author": new_comment["author"], "body": new_comment["body"], "creation_date": new_comment[
            "creation_date"], "last_modified": new_comment["last_modified"], "post_id": new_comment["post_id"], "self": request.url_root + "comments/" + new_comment_id}

        # Make response, headers, status code
        res = make_response(json.dumps(return_comment))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res


@app.route('/comments/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def comments_delete(id):

    if 'Authorization' not in request.headers:
        return ({"Error": "Missing JWT"}, 401)

    if verify_jwt(request) is False:
        return ({"Error": "Invalid JWT"}, 401)

    payload = verify_jwt(request)

    if request.method == 'GET':

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get comment for given id
        comment_key = client.key(COMMENTS, int(id))
        comment = client.get(key=comment_key)

        # If no comment, error
        if not comment:
            return ({"Error": "No comment with this comment_id exists"}, 403)

        if comment["author"] != payload["sub"]:
            return ({"Error": "Comment is owned by someone else"}, 403)

        # Return comment appropriately
        return_comment = {"id": id, "author": comment["author"], "body": comment["body"], "creation_date": comment[
            "creation_date"], "last_modified": comment["last_modified"], "post_id": comment["post_id"], "self": request.url_root + "comments/" + id}

        res = make_response(json.dumps(return_comment))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res

    # Delete a Comment
    elif request.method == 'DELETE':

        if 'Authorization' not in request.headers:
            return ({"Error": "Missing JWT"}, 401)

        if verify_jwt(request) is False:
            return ({"Error": "Invalid JWT"}, 401)

        # Get comment of given id
        comment_key = client.key(COMMENTS, int(id))
        comment = client.get(key=comment_key)

        # If no comment with id, error
        if not comment:
            return ({"Error": "No comment with this comment_id exists"}, 403)

        if comment["author"] != payload["sub"]:
            return ({"Error": "Comment is owned by someone else"}, 403)

        # If post, delete post
        client.delete(comment_key)
        return ('', 204)

    # Edit all attributes of comment
    elif request.method == 'PUT':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # Check for all required attributes
        if "body" not in content:
            return ({"Error": "The request object is missing at least one of the required attributes"}, 400)

        # Get comment
        comment_key = client.key(COMMENTS, int(id))
        comment = client.get(key=comment_key)

        # Check if comment of id exists
        if not comment:
            return ({"Error": "No comment with this comment_id exists"}, 403)
        
        if comment["author"] != payload["sub"]:
            return ({"Error": "Comment is owned by someone else"}, 403)

        # Update comment contents
        comment.update(
            {"body": content["body"], "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})

        client.put(comment)

        return_comment = {"id": id, "author": comment["author"], "body": comment["body"], "creation_date": comment[
            "creation_date"], "last_modified": comment["last_modified"], "post_id": comment["post_id"], "self": request.url_root + "comments/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_comment))
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Location', return_comment["self"])
        res.status_code = 303
        return res

    elif request.method == 'PATCH':

        # Check if request is json
        if request.get_json() is None:
            return ({"Error": "Request is an unsupported media type. Request must be JSON"}, 415)

        # Check if client accepts json
        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Server can only return application/json"}, 406)

        # Get new content
        content = request.get_json()

        # If no attribute is given, error
        if "body" not in content:
            return ({"Error": "No attribute was given"}, 400)

        # Get comment
        comment_key = client.key(COMMENTS, int(id))
        comment = client.get(key=comment_key)

        # Check if comment of id exists
        if not comment:
            return ({"Error": "No comment with this comment_id exists"}, 404)

        if comment["author"] != payload["sub"]:
            return ({"Error": "Comment is owned by someone else"}, 403)

        # Update comment contents
        comment.update(
            {"body": content["body"], "last_modified": date.today().strftime("%m/%d/%Y") + " " + time.strftime("%H:%M:%S")})

        client.put(comment)

        return_comment = {"id": id, "author": comment["author"], "body": comment["body"], "creation_date": comment[
            "creation_date"], "last_modified": comment["last_modified"], "post_id": comment["post_id"], "self": request.url_root + "comments/" + id}

        # Make response, location header, status code
        res = make_response(json.dumps(return_comment))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res


# ------------------------------- Auth0 FUNCTIONALITY ----------------------------------------------- #


@ app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL)


@ app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


@ app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    idtoken = auth0.authorize_access_token()["id_token"]
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    print(userinfo)
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    session['jwt'] = idtoken

    # Add user to the "users" entity after login/signup if user isn't in the database
    new_user_key = client.key(USERS, userinfo['sub'])

    if not client.get(new_user_key):
        new_user = datastore.entity.Entity(key=new_user_key)
        new_user.update({"id": userinfo['sub'], "email": userinfo['email']})
        client.put(new_user)

    return redirect('/userinfo')


@ app.route('/ui_login')
def ui_login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL)


@ app.route('/userinfo')
@ requires_auth
def userinfo():
    return render_template('userinfo.html',
                           userinfo=session['profile'],
                           jwt=session['jwt'])


@ app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for(
        'home', _external=True), 'client_id': 'lS6gVZBkMZzyn24f1ug5W4iC8n7Xrux3'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


# ------------------------------------------------------------------------------ #
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
