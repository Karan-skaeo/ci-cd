from flask import Flask, render_template, request, redirect, url_for,jsonify
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime
import markdown
from sqlalchemy.orm import relationship
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity,jwt_required,get_jwt
import os
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
db = SQLAlchemy(app)
jwt = JWTManager(app)

#database schemas
class Blog(db.Model):
    __tablename__ = "blogs"
    id = db.Column(db.Integer, primary_key=True, index=True)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String)    
    date_posted = db.Column(db.DateTime) 
    content = db.Column(db.Text, nullable=False)
    conclusion = db.Column(db.Text, nullable=True)

    @property
    def content_html(self):
        # Normalize line endings and ensure proper spacing
        formatted_content = self.content.strip()
        
        # Ensure headers have proper spacing
        formatted_content = formatted_content.replace('\n###', '\n\n###')
        
        # Ensure proper list formatting
        formatted_content = formatted_content.replace('\n*', '\n\n*')
        formatted_content = formatted_content.replace('\n1.', '\n\n1.')
        
        # Ensure paragraphs have proper spacing
        formatted_content = '\n\n'.join(
            para.strip() for para in formatted_content.split('\n\n')
        )
        
        return markdown.markdown(
            formatted_content,
            extensions=[
                'fenced_code',
                'tables',
                'extra',
                'nl2br',
                'sane_lists'
            ],
            output_format='html5',
            extension_configs={
                'markdown.extensions.extra': {
                    'markdown_in_html': True
                }
            }
        )

    @property
    def conclusion_html(self):
        if self.conclusion:
            # Apply same formatting to conclusion
            formatted_conclusion = self.conclusion.strip()
            formatted_conclusion = formatted_conclusion.replace('\n###', '\n\n###')
            formatted_conclusion = formatted_conclusion.replace('\n*', '\n\n*')
            formatted_conclusion = formatted_conclusion.replace('\n1.', '\n\n1.')
            formatted_conclusion = '\n\n'.join(
                para.strip() for para in formatted_conclusion.split('\n\n')
            )
            
            return markdown.markdown(
                formatted_conclusion,
                extensions=[
                    'fenced_code',
                    'tables',
                    'extra',
                    'nl2br',
                    'sane_lists'
                ],
                output_format='html5',
                extension_configs={
                    'markdown.extensions.extra': {
                        'markdown_in_html': True
                    }
                }
            )

blacklist_tokens = set()
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist_tokens

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'message': 'The token has been revoked'
    }), 401

@app.route('/login')
def login_page():
    return render_template('login.html'), 200

@app.route('/api/login', methods=['POST'])
def login_api():
    """API for logging in the user"""
    data = request.get_json()
    user = data.get('username')
    password = data.get('password')
    if not user or not password:
        return jsonify({'error': 'Missing user or password'}), 400
    if user != os.environ.get('APP_USERNAME_OR_EMAIL'):
        return jsonify({'error': 'Invalid user email'}), 401
    if password != os.environ.get('APP_PASSWORD'):
        return jsonify({'error': 'Invalid password'}), 401
    #the user is authenticated and the access token is created
    access_token = create_access_token(identity=str(user))
    return jsonify({'access_token': access_token}), 200


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout_api():
    try:
        jwt_token = get_jwt()
        blacklist_tokens.add(jwt_token['jti'])
        return jsonify({'status': 'success', 'message': 'User logged out successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'{str(e)}'})


@app.route('/')
def index():
    """Welcome page"""
    posts = Blog.query.order_by(Blog.date_posted.desc()).all()
    return render_template('home.html', posts=posts), 200

@app.route('/post/<int:post_id>')
def post(post_id):
    """API for ndividual blog post and render"""
    post = Blog.query.filter_by(id=post_id).one()
    return render_template('show-post.html', post=post), 200

@app.route('/add')
def add():
    """render add post page and form"""
    return render_template('add-post.html'), 200

@app.route('/addpost', methods=['POST'])
@jwt_required()
def addpost():
    """API for creating the blog post and redirect home page"""
    user = get_jwt_identity()
    jwt_token = get_jwt()
    if jwt_token['jti'] in blacklist_tokens:
        return jsonify({'status': 'error', 'message': 'token expires'}), 401
    if user != os.getenv('APP_USERNAME_OR_EMAIL'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    data = request.get_json()
    title = data.get('title')
    author = data.get('author')
    content = data.get('content')
    conclusion = data.get('conclusion')
    
    post = Blog(
        title=title,
        author=author,
        content=content,
        conclusion=conclusion,
        date_posted=datetime.now()
    )
    db.session.add(post)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Post added successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)