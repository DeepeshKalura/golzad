
from functools import lru_cache
import os
from fastapi import FastAPI, File, Form, Request, Response, UploadFile, HTTPException, Query, Depends, status, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel 
from typing import Annotated, Optional
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


origins = ["*"]

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
UPLOAD_DIRECTORY = os.path.dirname(os.path.abspath(__file__))+"/.."+"/upload"

@app.get("/")
async def root():
    return FileResponse (path="template/root.html")

@app.get("/favicon")
def app_icon():
    return FileResponse(path="template/images/favicon.ico")

@app.get(path="/hero-image")
def hero_logo():
    return FileResponse(path="template/images/panda.jpeg")



# I need your name and need password to access file 
class Preference(BaseModel): 
    name: str
    password: str 


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)



class UsersRequest(BaseModel):
    name: str 
    password: str 
    email: str

@app.get(path="/register")
async def get_register():
    return FileResponse(path="template/register.html")

@app.post(path="/register")
async def create_user(user_request: UsersRequest, response: Response, session: SessionDep):
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



@app.get(path="/authenticate")
def get_auth_user():
    return FileResponse("template/login.html")


@app.post(path="/authenticate")
async def auth_user(session: SessionDep, response: Response, user: Annotated[ OAuth2PasswordRequestForm, Depends()], settings:Settings = Depends(get_settings)):
    

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
            response.set_cookie(key="access_token", value=token)
            return {
                "access_token": token
            }
    

    
class BucketRequest(BaseModel):
    name: str 


class Bucket(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    user_id:int  = Field(foreign_key="user.id")




@app.post(path="/bucket")
async def create_buget(bucket_request: BucketRequest,  session: SessionDep, request: Request ):
    
    token = request.cookies.get("access_token")

    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")


    try: 
        

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
        folder_name = f"{UPLOAD_DIRECTORY}/{bucket_request.name}"
        os.mkdir(folder_name)
        os.mkdir( folder_name+"/private") 
        
        return {
            "message": f"your bucket named {bucket_request.name} has been create "
        }

    
        
        
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    

# TODO: store the file
@app.post(path="/store/{bucket_name}")
async def store_files():
    pass


# TODO: get the file


class BucketObjectCreate(BaseModel):
    name: str
    is_folder: bool = False
    is_private: bool = False
    bucket_id: int

@app.post("/store")
async def store_file_or_create_folder(
    request: Request, 
    body: BucketObjectCreate, 
    session: SessionDep,
    file: Optional[UploadFile] = None,
):
    # Validate access token
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token not found in cookies"
        )

    # Get current user
    user: User = await get_current_user(
        session=get_normal_instance_session(), 
        token=token, 
        settings=Settings()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Please provide valid token"
        )

    # Validate bucket
    bucket = session.get(Bucket, body.bucket_id)
    if not bucket or bucket.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Bucket not found"
        )

    # Create folder scenario
    if body.is_folder:
        folder_object = BucketObject(
            name=body.name,
            size=0,
            is_folder=True,
            is_private=body.is_private,
            user_id=user.id,
            bucket_id=bucket.id,
            path=f"{UPLOAD_DIRECTORY}/{bucket.name}/{'private/' if body.is_private else ''}{body.name}"
        )
        
        # Create physical directory
        os.makedirs(folder_object.path, exist_ok=True)
        
        session.add(folder_object)
        session.commit()
        session.refresh(folder_object)
        
        return {
            "message": f"Folder {body.name} created successfully",
            "folder_id": folder_object.id
        }

    # File upload scenario
    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="No file provided"
        )

    # Determine storage path
    base_directory = f"{UPLOAD_DIRECTORY}/{bucket.name}"
    directory = f"{base_directory}/{'private' if body.is_private else ''}"
    os.makedirs(directory, exist_ok=True)

    # Save file
    full_path = os.path.join(directory, file.filename)
    with open(full_path, "wb") as f:
        f.write(await file.read())

    # Create BucketObject for file
    file_object = BucketObject(
        name=file.filename,
        size=os.path.getsize(full_path),
        is_folder=False,
        is_private=body.is_private,
        path=full_path,
        user_id=user.id,
        bucket_id=bucket.id,
    )

    session.add(file_object)
    session.commit()
    session.refresh(file_object)

    return {
        "message": f"File {file.filename} uploaded successfully",
        "file_id": file_object.id,
    }



@app.get("/home")
def get_home():
    return FileResponse(path="template/home.html")

@app.get("/user")
async def get_profile(request: Request):

    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")

    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }

@app.get("/bucket")
async def get_bucket(request: Request, session: SessionDep):
    token = request.cookies.get("access_token")

    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")
    

    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())

    if not user: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    

    statement = select(Bucket).where(Bucket.user_id == user.id)
    bucket = session.exec(statement).all()
    
    
    return {
       "buckets":  [{"id": b.id, "name": b.name} for b in bucket]
    }

@app.get("/profileImage")
async def get_profile_image():
    return FileResponse("upload/himmeltheHero.png")


class FileInfo(BaseModel):
    name: str
    size: int
    type: str
    is_directory: bool

   


@app.get(path="/files/{bucket_id}")
async def get_files(request: Request, session: SessionDep, bucket_id:int  ):
    token = request.cookies.get("access_token")

    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")
    

    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())

    if not user: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    

    statement = select(Bucket).where(Bucket.id == bucket_id)
    bucket = session.exec(statement).one()


    # calling the files from the bucket

    files = f"{UPLOAD_DIRECTORY}/{bucket.name}"


    file_list: list[FileInfo] = []
    
    for file_name in os.listdir(files):
        file_path = os.path.join(files, file_name)
        file_info = FileInfo(
            name=file_name,
            size=os.path.getsize(file_path),
            type="directory" if os.path.isdir(file_path) else "file",
            is_directory=os.path.isdir(file_path)
        )
        file_list.append(file_info)
    
    return {
    
        "files": file_list
    }



class RenameBucketRequestModel(BaseModel):
    new_name: str
    old_name: str


@app.put("/bucket/rename/{bucket_id}")
async def rename_bucket(
    request: Request, 
    session: SessionDep, 
    bucket_id: str, 
    bucket_rename: RenameBucketRequestModel
):
    token = request.cookies.get("access_token")
    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")

    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())
    
    statement = select(Bucket).where(Bucket.name == bucket_rename.old_name, Bucket.user_id == user.id)
    existing_bucket = session.exec(statement).first()
    
    if not existing_bucket:
        raise HTTPException(status_code=404, detail="Bucket not found")
    
    existing_bucket.name = bucket_rename.new_name
    session.add(existing_bucket)
    session.commit()
    
    return {"message": "Bucket renamed successfully"}

@app.delete("/bucket/{bucket_id}")
async def delete_bucket(
    request: Request, 
    bucket_id: str, 
    session: SessionDep
):
    token = request.cookies.get("access_token")

    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")

        
    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())
    
    statement = select(Bucket).where(Bucket.id == bucket_id, Bucket.user_id == user.id)
    bucket = session.exec(statement).first()
    
    if not bucket:
        raise HTTPException(status_code=404, detail="Bucket not found")
    
    # Delete associated files first
    file_statement = select(BucketObject).where(BucketObject.bucket_id == bucket.id)
    files = session.exec(file_statement).all()
    
    for file in files:
        # Optional: Delete physical file from storage
        os.remove(file.path)
        session.delete(file)
    
    session.delete(bucket)
    session.commit()
    
    return {"message": "Bucket and its files deleted successfully"}



class BucketObject(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    size: int 
    is_folder: bool 
    is_private: bool
    path: str
    user_id:int  = Field(foreign_key="user.id")
    bucket_id:int = Field(foreign_key="bucket.id")





@app.get("/file/{file_id}")
async def get_file(
    request: Request, 
    file_id: int, 
    session: SessionDep
):
    token = request.cookies.get("access_token")
    if not token: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found in cookies")

    user = await get_current_user(session=get_normal_instance_session(), token=token, settings=Settings())
    
    file_statement = select(BucketObject).where(BucketObject.id == file_id)
    file = session.exec(file_statement).first()
    
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check file permissions
    if file.is_private and file.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return FileResponse(path=file.path)


@app.get("/sharing-illustration")
def sharing_illustration():
    return FileResponse("template/images/share.svg")    