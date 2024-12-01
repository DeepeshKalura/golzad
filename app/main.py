
from functools import lru_cache
import os
from typing import Any, Generator, Optional 
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Query, Depends, status, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel 
from typing import Annotated
from sqlmodel import Field, Session, SQLModel, create_engine, select
import uuid
from passlib.context import CryptContext
from pydantic_settings import BaseSettings
import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


# configuration
class Settings(BaseSettings):
    private_key: str  = os.getenv("PRIVATE_KEY")
    algorithm: str =  os.getenv("ALGORITHM")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))



class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    email:str 
    hash_password: str 



# now creating an engine 
sqlite_file_name = "app/server.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

def get_normal_instance_session():
    return Session(engine)


SessionDep = Annotated[Session, Depends(get_session)]
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="authenticate")


@lru_cache
def get_settings():
    return Settings()


app = FastAPI(title="Golzad")


origins = ["http://127.0.0.0"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# async context manage ( on behave of this event)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# upload na kerna 
UPLOAD_DIRECTORY = os.path.dirname(os.path.abspath(__file__)) + "/upload"

@app.get("/")
async def root():
    return FileResponse (path="template/root.html")



# I need your name and need password to access file 
class Preference(BaseModel): 
    name: str
    password: str 


class UsersRequest(BaseModel):
    name: str 
    password: str 
    email: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)



@app.post(path="/register")
async def create_user(user_request: UsersRequest, session: SessionDep):
    user = User( email=user_request.email, name=user_request.name,  hash_password=hash_password(user_request.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return  {
        "id": user.id,
        "name": user.name, 
        "email": user.email         
    }



def authenticate_user(id: int, password: str, session: SessionDep):
    statement = statement = select(User).where(User.id == id)
    user: User = session.exec(statement).one()
    if not user:
        return False
    if not verify_password(password, user.hash_password):
        return False
    return user



async def get_current_user(
    session, 
    token: str, 
    settings: Settings)-> User:
    try:
        payload = jwt.decode(token, settings.private_key, algorithms=[settings.algorithm])
        print(payload)
        id: int = payload.get("id")
        if not id:
            raise HTTPException( status_code=status.HTTP_401_UNAUTHORIZED, detail="Payload has issue")

        statement = select(User).where(User.id == id)
        user = session.exec(statement).one()
        if not user:
            raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="This is impossible should be reach this state",
    )

        return user
    except (InvalidTokenError, KeyError):
                    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="How can be your token so wrong",
    )




@app.post(path="/authenticate")
async def auth_user(session: SessionDep, user: Annotated[ OAuth2PasswordRequestForm, Depends()], settings:Settings = Depends(get_settings)):
    

    statement = select(User).where(User.email == user.username)
    person = session.exec(statement).one()

    if(person == None):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail= f"There exit no user for {user.username}")

    else: 
        if(  not verify_password(user.password, person.hash_password)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please write correct password")

        else: 

            payload = {
                "id": person.id,
                "name" : person.name,
                "email": person.email,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
            }

    

            token = jwt.encode(
                payload, settings.private_key, algorithm=settings.algorithm
            )

            # cookies mey dalte 
            return {
                "access_token": token
            }
    

    
class BucketRequest(BaseModel):
    name: str 


class Bucket(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    user_id:int  = Field(foreign_key="user.id")


class AuthHeaders(BaseModel):
    Authorization: str

@app.post(path="/bucket")
async def create_buget(bucket_request: BucketRequest,  session: SessionDep, header: Annotated[AuthHeaders, Header()] ):
    

    try: 
        
        # check the token 

        print(header.Authorization)

        # Bearer ""

        token = header.Authorization[7:]

        user: User = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())

        print(user)
        if(user == None):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="you are not autheticated")


        # check the bucket
        
        statement = select(Bucket).where(Bucket.name == bucket_request.name)
        bucket = session.exec(statement).one_or_none()

        if(bucket):
            raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="your bucket is already been create")



        


        
        bucket = Bucket(name=bucket_request.name, user_id= user.id)

        session.add(bucket)
        session.commit()
        session.refresh(bucket)
        folder_name = f"{bucket_request.name}_{id}"
        os.mkdir(folder_name)
        
        return {
            "message": f"your bucket named {bucket_request.name} has been create "
        }

    
        
        
    except InvalidTokenError:
        raise credentials_exception

    

# TODO: store the file
@app.post(path="/store/{bucket_name}")
async def store_files():
    pass


# TODO: get the file


@app.post("/store")
async def store_file(
    file: UploadFile,
):
    # Construct preference object if provided
    preference = None
    if (name == None and password == None):
        preference = None
    else: 
        preference = Preference(name=name, password=password)

    url = ""
    if preference:
        user_directory = os.path.join(UPLOAD_DIRECTORY, preference.name)
        if not os.path.exists(user_directory):
            return {"message": "User preference not found"}

        password_file = os.path.join(user_directory, "password.txt")
        if os.path.exists(password_file):
            with open(password_file, "r") as f:
                stored_password = f.read()
            if stored_password != preference.password:
                return {"message": "Invalid password"}
        else:
            return {"message": "Password file not found"}

        file_location = os.path.join(user_directory, file.filename)
        with open(file_location, "wb") as f:
            f.write(await file.read())

        url = f"http://127.0.0.1:8000/store/{preference.name}/{file.filename}"
    else:
        file_location = os.path.join(UPLOAD_DIRECTORY, file.filename)
        with open(file_location, "wb") as f:
            f.write(await file.read())

        url = f"http://127.0.0.1:8000/store/{file.filename}"

    return {
        "message": "Your file is successfully stored",
        "url": url,
    }



@app.get("/store/{bucket}/{file_name}")
async def get_store(filename: str,u: str | None = None, p: str | None = None ):
    print(filename)
    file_location = UPLOAD_DIRECTORY + "/"
    if (u != None and p != None ):
            file_location = os.path.join(file_location, u)

            password_file = os.path.join(file_location, "password.txt")
    
            if os.path.exists(password_file):
                with open(password_file, "r") as f:
                    stored_password = f.read()
                if stored_password == p:
                    file_location = os.path.join(file_location, filename)
                else:
                    return {"message": "Invalid password"}
            else:
                return {"message": "Please set a correct reference"}




    else: 
        file_location = os.path.join(file_location, filename)

    
    if not os.path.exists(file_location):
        return {"message": "File not found"}

    return FileResponse(path=file_location)
     





