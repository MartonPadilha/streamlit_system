import streamlit as st
import sqlite3
import bcrypt

def create_connection():
    conn = sqlite3.connect('users.db')
    return conn

def create_users_table():
    conn = create_connection()
    cursor = conn.cursor()
    sql = """
        CREATE TABLE IF NOT EXISTS users(
            id integer primary key autoincrement,
            username text unique,
            password text
        )
    """
    cursor.execute(sql)
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) values (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error('User has been created!')
    finally:
        conn.close()

def login_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("select password from users where username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return bcrypt.checkpw(password.encode(), result[0])
    return False

def show_login():
    st.subheader("Login")
    username = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")

    if st.button("Entrar"):
        if login_user(username, senha):
            st.success(f"Bem-vindo(a), {username}!")
            st.session_state["logged_in"] = True
            st.session_state["user"] = username
            st.session_state["page"] = "main"
            st.rerun()
        else:
            st.error("Usuário ou senha incorretos.")

def show_signup():
    st.header("Tela de cadastro")
    username = st.text_input("User")
    password = st.text_input("Senha", type="password")
    r_password = st.text_input("Repita a Senha", type="password")

    if st.button('Cadastrar'):
        if username and password and r_password:
            if password == r_password:
                add_user(username, password)
                st.success("Usuário criado com sucesso!")
            else:
                st.error("As senhas devem ser iguais!")
        else:
            st.warning('Todos os campos devem ser preenchidos')
    
def show_main_page():
    st.success(f"Bem-vindo(a), {st.session_state['user']}!")
    st.write("Você está na área interna.")
    if st.button("Sair"):
        st.session_state.clear()

def main():
    st.title("Tela")

    create_users_table()

    if "page" not in st.session_state:
        st.session_state["page"] = "login"
    if st.session_state.get("logged_in"):
        show_main_page()
    else:
        menu = ['Login', 'Cadastro']
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Login":
            show_login()
        if choice == "Cadastro":
            show_signup()
        



if __name__ == "__main__":
    main()
