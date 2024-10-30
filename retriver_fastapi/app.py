from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
async def home():
    return {"body":"Retriver fast API"}

if __name__ == "__main__":
   uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=True)