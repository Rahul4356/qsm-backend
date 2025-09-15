from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "QMS Backend Running"}

@app.get("/api/health")
def health():
    return {"status": "healthy"}

@app.get("/api/register")
def register():
    return {"message": "Register endpoint"}

@app.get("/api/login")
def login():
    return {"message": "Login endpoint"}

@app.post("/api/register")
def register_post():
    return {"message": "Register POST"}

@app.post("/api/login")
def login_post():
    return {"message": "Login POST"}
