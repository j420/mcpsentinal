# True positive: Python f-string in cursor.execute — the lightweight analyser
# handles Python patterns the AST analyser (TypeScript compiler) does not.
import psycopg2

def lookup(request):
    name = request.form['name']
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
