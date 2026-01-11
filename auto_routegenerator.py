import os
from flask import render_template

def auto_register_routes(app, templates_dir="templates"):
    for root, dirs, files in os.walk(templates_dir):
        for f in files:
            if f.endswith(".html"):
                # complete path relative to templates/
                rel_path = os.path.relpath(os.path.join(root, f), templates_dir).replace("\\", "/")
                
                # route path -> /Firstyear OR /subfolder/math
                route = "/" + rel_path.replace(".html", "")

                # endpoint name -> firstyear OR subfolder_math
                endpoint = rel_path.replace("/", "_").replace(".html", "").lower()

                # skip if endpoint already exists
                if endpoint in app.view_functions:
                    continue

                # create view function
                def view_func(template=rel_path):
                    return render_template(template)

                print(f"[AUTO] Route added: {route}  ->  template: {rel_path}  endpoint: {endpoint}")
                app.add_url_rule(route, endpoint, view_func)

# REGISTER AUTOMATIC ROUTES
auto_register_routes(app)
