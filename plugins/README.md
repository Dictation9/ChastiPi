# ChastiPi Plugins

This folder is for community and user-created plugins for ChastiPi.

## How to Create a Plugin
- Each plugin should be a Python file (`.py`) in this folder.
- Each plugin should define a function called `register_plugin(app)` or a class with a `register(app)` method.
- Plugins can add routes, modify behavior, or add new features.

## Example Plugin
```python
# plugins/hello_plugin.py
def register_plugin(app):
    @app.route('/hello-plugin')
    def hello():
        return 'Hello from plugin!'
```

## How Plugins are Loaded
- All `.py` files in this folder will be loaded automatically at startup.
- The `register_plugin(app)` function will be called with the main Flask app instance.

## Contributing
- Please keep plugins safe, documented, and respectful.
- PRs for new plugins are welcome! 