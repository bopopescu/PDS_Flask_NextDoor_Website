import sys

from flask import Flask, render_template, request, jsonify, session, redirect, escape, url_for
from datetime import datetime
import bcrypt
from getpass import getpass

class ServerError(Exception): pass

def loginForm(db, form):
	error = None
	try:
		username = form['username']
		cur = db.query("SELECT COUNT(1) FROM signup_Details WHERE username = %s", [username])

		if not cur.fetchone()[0]:
			raise ServerError('Incorrect username / password')
		print(username)
		password = form['password']
		print(password)
		cur = db.query("SELECT pwd FROM signup_Details WHERE username = %s;", [username])


		for row in cur.fetchall():

			#if (password , row[0]):
			if (password == row[0]):
				session['username'] = form['username']
				return error

		raise ServerError('Incorrect username / password')
	except ServerError as e:
		error = str(e)
		return error

def registerUser(db, form, ROUNDS):
	error = None
	try:
		username = form['username']
		password = form['password']
		print(username)
		print(password)

		#master_secret_key = getpass('tell me the master secret key you are going to use')
		#salt = bcrypt.gensalt()
		#combo_password = password + salt
		#hashed_password = bcrypt.hashpw(combo_password, salt)

		if not username or not password:
			raise ServerError('Fill in all fields')

		#password = bcrypt.hashpw(str(password).encode('utf-8'), bcrypt.gensalt(ROUNDS))

		cur = db.query("SELECT COUNT(*) FROM signup_Details WHERE username = %s", [username])
		c = cur.fetchone()
		s = "INSERT INTO signup_Details (`username`, `pwd`, `salt_Key`, `signuptime`) VALUES (%s,%s,%s,%s)"
		if c[0] == 0:
			cur = db.query(s, [username, password,'', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'))])
			return None
		else:
			return "User exists"
	except ServerError as e:
		error = str(e)
		return error

def getUsers(db):
	error = None
	try:
		userlist = []
		cur = db.query("SELECT username FROM signup_Details")
		for row in cur.fetchall():
			userlist.append({'name': row[0]})
		return userlist
	except:
		error = "Failed"
		return error

def deleteUser(db, user):
	error = None
	try:
		cur = db.query("DELETE FROM signup_Details WHERE username = %s",[user])
		return None
	except:
		return "Failed"
def getUserBlockLinkInfo(db):
	error = None
	try:
		print('inside get user block info function')
		userName = str(session['username'])
		print(userName)
		args = [userName, '@Bid']
		res = db.cursor.callproc('Get_User_Block_Infor', args)
		print(res[1])
		if res[1] is None:
			return 0

		print(res[1])
		return res[1]
	except IOError as err:
		print("I/O error: {0}".format(err))
	except ValueError:
		print("Could not convert data to an integer.")
	except:
		print("Unexpected error:", sys.exc_info()[0])
		error = "Failed"
		return error