import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import http from "http";
import User from "./model.js";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.SECRET_KEY;

const app = express();
const server = http.createServer(app);

app.use(express.json());
app.use(cors());

// requests
app.post("/auth", async (req, res) => {
    const { email, password } = req.body;
    try {
        const token = await jwt.sign({ email }, SECRET_KEY);

        User.find({ email }, async (err, data) => {
            if (err)
                res.status(500).send(err);
            else {
                if (data.length === 0)
                    res.send("User does not exist")
                else {
                    const hashedPass = data[0].password;
                    const match = await bcrypt.compare(password, hashedPass);
                    if (match)
                        res.status(200).send({ auth: true, token });
                    else
                        res.status(200).send({ auth: false });
                }
            }
        });
    } catch (err) { console.log(err) };

});

app.post("/token", async (req, res) => {
    const { token } = req.body;

    try {
        const { email } = await jwt.verify(token, SECRET_KEY);

        User.find({ email }, (err, data) => {
            if (err)
                res.status(500).send(err);
            else {
                if (data.length === 0)
                    res.send("User does not exist")
                else {
                    res.status(200).send(data[0]);
                }
            }
        });

    } catch (err) { res.send(err) };

});

app.post("/new", async (req, res) => {
    const { userId, firstName, lastName, city, email, password } = req.body;

    try {
        const hashedPass = await bcrypt.hash(password, 10);
        const token = await jwt.sign({ email }, SECRET_KEY);
        const user = new User({ userId, firstName, lastName, city, email, password: hashedPass });
        user.save().then(() => {
            res.status(200).send(token);
        }).catch(err => res.status(400).send(err))
    } catch (err) { console.log(err) };

});

// connecting to mongo db
const MONGO_URL = `mongodb+srv://${process.env.DB_ADMIN}:${process.env.DB_PASSWORD}@cluster0.xxutl.mongodb.net/sac?retryWrites=true&w=majority`;
mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("connection: success");
}).catch(err => console.log(err));

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => console.log("Listening to PORT : " + PORT));