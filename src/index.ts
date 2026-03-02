import "dotenv/config";
import express, { Request, Response } from "express";

const app = express();

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).send("ok");
});

const port = Number(process.env.PORT || 10000);
app.listen(port, () => {
  console.log(`Listening on ${port}`);
});