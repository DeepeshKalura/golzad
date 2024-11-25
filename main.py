import os
from typing import Optional 
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel 

app = FastAPI(title="Golzad")


origins = ["http://127.0.0.0"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# upload na kerna 
UPLOAD_DIRECTORY = os.path.dirname(os.path.abspath(__file__)) + "/upload"

@app.get("/")
async def root():
    return FileResponse (path="template/root.html")



# I need your name and need password to access file 
class Preference(BaseModel): 
    name: str
    password: str 



@app.post(path="/preference")
async def create_user_prefernce(preference: Preference): 


    if not os.path.exists(UPLOAD_DIRECTORY + "/" + preference.name):
        os.makedirs(UPLOAD_DIRECTORY + "/" + preference.name)

        with open(UPLOAD_DIRECTORY + "/" + preference.name + "/password.txt", "w") as f:
            f.write(preference.password)
        return {
            "message": "Your preference has been saved successfully"
        }

    else: 
        return {
            "message" : "Your preference is already noted it cannot be change"
        }

@app.post("/store")
async def store_file(
    file: UploadFile,
    name: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
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



@app.get("/store/{filename}")
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
     
