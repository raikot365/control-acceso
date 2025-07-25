from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import os, logging
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
# import ssl, asyncio, aiomqtt
# import MySQLdb

logging.basicConfig(format='%(asctime)s - APP - %(levelname)s - %(message)s', level=logging.INFO)

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config['PERMANENT_SESSION_LIFETIME']=3600
app.config["MYSQL_USER"] = os.environ["MYSQL_USER"]
app.config["MYSQL_PASSWORD"] = os.environ["MYSQL_PASSWORD"]
app.config["MYSQL_DB"] = os.environ["MYSQL_DB"]
app.config["MYSQL_HOST"] = os.environ["MYSQL_HOST"]
mysql = MySQL(app)



def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# @app.route("/registrar_administrador", methods=["GET", "POST"])
# def registrar_administrador():
#     """Registrar usuario"""
#     if request.method == "POST":

#         # Ensure username was submitted
#         if not request.form.get("usuario"):
#             return "el campo usuario es oblicatorio"

#         # Ensure password was submitted
#         elif not request.form.get("password"):
#             return "el campo contraseña es oblicatorio"

#         passhash=generate_password_hash(request.form.get("password"), method='scrypt', salt_length=16)
#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO usuarios (usuario, hash) VALUES (%s,%s)", (request.form.get("usuario"), passhash[17:]))
#         if mysql.connection.affected_rows():
#             flash('Se agregó un usuario', 'success')  # usa sesión
#             logging.info("se agregó un usuario")
#         mysql.connection.commit()
#         return redirect(url_for('index'))

#     return render_template('registrar-administrador.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("usuario"):
            return "el campo usuario es oblicatorio"
        # Ensure password was submitted
        elif not request.form.get("password"):
            return "el campo contraseña es oblicatorio"

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM usuarios WHERE usuario LIKE %s", (request.form.get("usuario"),))
        rows=cur.fetchone()
        if(rows):
            if (check_password_hash('scrypt:32768:8:1$' + rows[2],request.form.get("password"))):
                session.permanent = True
                session["user_id"]=request.form.get("usuario")
                session["theme"] = "light"
                logging.info("se autenticó correctamente")
                return redirect(url_for('index'))
            else:
                flash('usuario o contraseña incorrecto', 'error')
                return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/')
@require_login
def index():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuario")
    usuarios = cur.fetchall()
    cur.execute("SELECT * FROM tarjeta")
    tarjetas = cur.fetchall()
    # logging.info(f"usuarios {usuarios[0]} y tarjetas {tarjetas[0]}")
    return render_template('index.html', usuarios=usuarios, tarjetas=tarjetas)


@app.route('/registrar_usuario', methods=['GET','POST'])
@require_login
def registrar_usuario():
    if request.method == 'POST':
        nombre = request.form['nombre']
        rol = request.form['rol']
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO usuario (nombre, rol) VALUES (%s,%s)", (nombre, rol))
        if mysql.connection.affected_rows():
            flash('Se agregó un usuario', 'success')  
            logging.info("se agregó un usuario")
        mysql.connection.commit()
        return redirect(url_for('index'))
    return render_template('registrar-usuario.html')



@app.route('/editar_usuario/<id>', methods=['GET','POST'])
@require_login
def editar_usuario(id):
    if request.method == 'POST':
        nombre = request.form['nombre']
        rol = request.form['rol']
        cur = mysql.connection.cursor()
        cur.execute("UPDATE usuario SET nombre=%s, rol=%s WHERE user_id=%s", (nombre, rol,id))
    if mysql.connection.affected_rows():
        flash(f'Se actualizó un usuario {nombre}', 'success')  # usa sesión
        logging.info("se actualizó un usuario")
        mysql.connection.commit()
    if request.method == 'GET':
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id,nombre, rol FROM usuario WHERE user_id=%s", (id))
        usuario = cur.fetchone()
        return render_template('editar-usuario.html', usuario=usuario)
    return redirect(url_for('index'))

@app.route('/eliminar_usuario/<id>', methods=['GET','POST'])
@require_login
def eliminar_usuario(id):
    cur = mysql.connection.cursor()
    try:
        cur.execute("DELETE FROM usuario WHERE user_id=%s", (id,))
        mysql.connection.commit()
    except Exception as e:
        flash(f'No se pudo eliminar el usuario {e}', 'error') 
        logging.info("no se pudo eliminar el usuario")
        return redirect(url_for('index'))
    # if mysql.connection.affected_rows():
    flash('Se eliminó un usuario', 'warning')
    logging.info("se eliminó un usuario")
    return redirect(url_for('index'))

@app.route('/desvincular_tarjeta/<id>', methods=['GET','POST'])
@require_login
def desvincular_tarjeta(id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE tarjeta SET user_id=NULL WHERE tarjeta_id=%s", (id,))
    mysql.connection.commit()
    flash('Se desvinculó una tarjeta', 'warning')
    logging.info("se desvinculó una tarjeta")
    return redirect(url_for('index'))

@app.route('/habilitar_tarjeta/<id>/<state>', methods=['POST'])
@require_login
def habilitar_tarjeta(id, state):
    state = 1 if int(state) == 0 else 0
    cur = mysql.connection.cursor()
    cur.execute("UPDATE tarjeta SET habilitada=%s WHERE tarjeta_id=%s", (state, id,))
    mysql.connection.commit()
    if state:
        flash('Se habilitó una tarjeta', 'success')
        logging.info("se habilitó una tarjeta")
    else:
        flash('Se deshabilitó una tarjeta', 'warning')
        logging.info("se deshabilitó una tarjeta")
    return redirect(url_for('index'))

@app.route('/vincular_tarjeta_index/<id>', methods=['GET','POST'])
@require_login
def vincular_tarjeta_index(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuario")
    usuarios = cur.fetchall()
    cur.execute("SELECT * FROM tarjeta WHERE tarjeta_id=%s", (id,))
    tarjeta = cur.fetchall()
    tarjeta = tarjeta[0]
    return render_template('vincular-tarjeta.html', usuarios=usuarios, tarjeta=tarjeta)

@app.route('/vincular_tarjeta/<id>', methods=['GET','POST'])
@require_login
def vincular_tarjeta(id):
    user_id = request.form.get('user_id')
    # logging.info(f"id {id} user_id {user_id}")
    if request.method == 'POST':
        try:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE tarjeta SET user_id=%s WHERE tarjeta_id=%s", (user_id,id,))
            mysql.connection.commit()
            flash('Se vinculó una tarjeta', 'success')
            logging.info("se vinculó una tarjeta")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'No se pudo vincular la tarjeta {e}', 'error') 
            logging.info("no se pudo vincular la tarjeta")
            return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/eliminar_tarjeta/<id>', methods=['GET','POST'])
@require_login
def eliminar_tarjeta(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT codigo FROM tarjeta WHERE tarjeta_id=%s",(id,))
    codigo_tarjeta = cur.fetchall()[0]
    logging.info(f"codigo_tarjeta {codigo_tarjeta}")
    cur.execute("DELETE FROM acceso WHERE codigo_tarjeta=%s",(codigo_tarjeta,))
    try:
        cur.execute("DELETE FROM tarjeta WHERE tarjeta_id=%s", (id,))
        mysql.connection.commit()
        flash('Se eliminó una tarjeta', 'warning')
    except Exception as e:
        flash(f'No se pudo eliminar la tarjeta {e}', 'error') 
        logging.info("no se pudo eliminar la tarjeta")
        return redirect(url_for('index'))
    logging.info("se eliminó una tarjeta")
    return redirect(url_for('index'))

@app.route('/editar_tarjeta/<id>', methods=['GET','POST'])
@require_login
def editar_tarjeta(id):
    if request.method == 'POST':
        codigo = request.form['codigo']
        tipo = request.form['tipo']
        habilitada = request.form['habilitada']
        acceso = request.form['acceso']
        flag_hora = False
        if request.form['hora_inicio'] == '' and request.form['hora_fin'] == '':
            flag_hora = True
        else:
            hora_inicio = request.form['hora_inicio']
            hora_fin = request.form['hora_fin']

        cur = mysql.connection.cursor()
        if flag_hora:
            cur.execute("UPDATE tarjeta SET codigo=%s, tipo=%s, habilitada=%s, acceso=%s WHERE tarjeta_id=%s", (codigo,tipo,habilitada,acceso,id,))
        else:
            cur.execute("UPDATE tarjeta SET codigo=%s, tipo=%s, habilitada=%s, acceso=%s, hora_inicio=%s, hora_fin=%s WHERE tarjeta_id=%s", (codigo,tipo,habilitada,acceso,hora_inicio,hora_fin,id,))
        if mysql.connection.affected_rows():
            flash(f'Se actualizó una tarjeta {codigo}', 'success') 
            logging.info("se actualizó una tarjeta")
            mysql.connection.commit()
    if request.method == 'GET':
        cur = mysql.connection.cursor()
        cur.execute("SELECT codigo, tarjeta_id, tipo, habilitada, acceso, hora_inicio, hora_fin FROM tarjeta WHERE tarjeta_id=%s", (id))
        tarjeta = cur.fetchone()
        cur.execute("SELECT puerta_id, descripcion, codigo_puerta FROM puerta")
        puertas = cur.fetchall()
        return render_template('editar-tarjeta.html', tarjeta=tarjeta, puertas=puertas)
    return redirect(url_for('index'))

@app.route('/editar_acceso/<id>', methods=['GET','POST'])
@require_login
def editar_acceso(id):
    try:
        codigo_puerta = request.form.get('codigo_puerta')
        cur = mysql.connection.cursor()
        cur.execute("SELECT codigo FROM tarjeta WHERE tarjeta_id=%s", (id,))
        codigo_tarjeta = cur.fetchall()
        
        if request.method == 'POST':
            cur.execute("INSERT INTO acceso (codigo_tarjeta, codigo_puerta) VALUES (%s, %s)", (codigo_tarjeta, codigo_puerta,))
            mysql.connection.commit()
            flash('Se agregó un acceso', 'success')
            logging.info("se agregó un acceso")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'No es posible agregar el acceso {e}', 'error')
        logging.info("no se pudo agregar el acceso")
        return redirect(url_for('editar_tarjeta', id=id))

    
    return redirect(url_for('index'))

@app.route('/registar_tarjeta', methods=['GET','POST'])
@require_login
def registrar_tarjeta():
    if request.method == 'GET':
        return render_template('registrar-tarjeta.html')
    if request.method == 'POST':
        codigo = request.form['codigo']
        tipo = request.form['tipo']
        habilitada = request.form['habilitada']
        acceso = request.form['acceso']
        flag_hora = False
        if request.form['hora_inicio'] == '' and request.form['hora_fin'] == '':
            flag_hora = True
        else:
            hora_inicio = request.form['hora_inicio']
            hora_fin = request.form['hora_fin']

        cur = mysql.connection.cursor()
        if flag_hora:
            cur.execute("INSERT INTO tarjeta (codigo, tipo, habilitada, acceso) VALUES (%s, %s, %s, %s)", (codigo, tipo, habilitada, acceso,))
        else:
            cur.execute("INSERT INTO tarjeta (codigo, tipo, habilitada, acceso, hora_inicio, hora_fin) VALUES (%s, %s, %s, %s, %s, %s)", (codigo, tipo, habilitada, acceso, hora_inicio, hora_fin,))
        if mysql.connection.affected_rows():
            flash(f'Se agregó una tarjeta {codigo}', 'success') 
            logging.info("se agregó una tarjeta")
            mysql.connection.commit()
        return redirect(url_for('index'))


@app.route('/historial_acceso', methods=['GET'])
@require_login
def historial_acceso():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM registro ORDER BY fecha DESC")
    registros = cur.fetchall()
    # logging.info(f"historial_acceso {registros}")
    return render_template('historial-acceso.html', registros=registros)



@app.route("/logout")
@require_login
def logout():
    session.clear()
    logging.info("el usuario {} cerró su sesión".format(session.get("user_id")))
    return redirect(url_for('index'))


@app.route('/change_theme', methods=['POST'])
@require_login
def change_theme():
    tema_actual = session.get('theme')
    session['theme'] = 'dark' if tema_actual == 'light' else 'light'
    return '', 204


