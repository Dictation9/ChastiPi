def register_plugin(app):
    @app.route('/hello-plugin')
    def hello():
        return 'Hello from plugin!' 