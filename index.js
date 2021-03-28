const express = require('express');
var cors = require("cors");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');
const mongodb = require('mongodb');

const { authenticate, isValidRole } = require('./helpers/authorization');

const app = express();
const mongoClient = mongodb.MongoClient;

const dbUrl = process.env.dbUrl || "mongodb://127.0.0.1:27017";
const port = process.env.PORT || 4001

//middleware
app.use(express.json());
app.use(cors());

//get all users
app.get('/', async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db("Url_Shortner_db");
        let data = await db.collection("user_details").find().toArray();
        // let data = await db.collection("user_details").find().project({ password: 0 }).toArray();
        res.status(200).json(data);
        clientInfo.close();
    }
    catch (error) {
        console.log(error);
    }
})

//register-user
app.post('/register', async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db("Url_Shortner_db");
        let found = await db.collection("user_details").findOne({ email: req.body.email });
        if (found) {
            res.status(400).json({ message: "user already exists" })
        } else {
            let salt = await bcrypt.genSalt(10);
            let hash = await bcrypt.hash(req.body.password, salt);
            console.log(req.body);
            req.body.password = hash;
            await db.collection('user_details').insertOne(req.body);
            res.status(200).json({ message: "user updated" })
        }
        clientInfo.close();
    }
    catch (error) {
        console.log(error);
    }
})

//user-login
app.post('/login', async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db("Url_Shortner_db");
        let found = await db.collection("user_details").findOne({ email: req.body.email });
        if (found) {
            let isValid = await bcrypt.compare(req.body.password, found.password)
            if (isValid) {
                let token = await jwt.sign({ user_id: found._id, role: found.role }, process.env.JWT_KEY)
                // console.log(token)
                res.status(200).json({ message: "login successful", token })
            } else {
                //401 Unauthorized
                res.status(401).json({ message: "login Unsuccessful" })
            }
        } else {
            //400
            res.status(404).json({ message: "user not registered" })
        }
        clientInfo.close();
    }
    catch (error) {
        console.log(error);
    }
})

//only user will be allowed to get the data 
app.get('/if-user-loggedin', [authenticate, isValidRole("user")], async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db("Url_Shortner_db");
        let data = await db.collection("user_details").find().toArray();
        res.status(200).json({message: "user created",data});
        clientInfo.close();
    }
    catch (error) {
        console.log(error);
    }
})

app.listen(port, () => console.log("App is listening"))

