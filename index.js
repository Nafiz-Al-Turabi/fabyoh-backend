const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');
require('dotenv').config()
const app = express();
const port = process.env.PORT || 5000;

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// middleware
app.use(cors());
app.use(express.json());

// Mongo DB default code..
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.f75tpn0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const uri = "mongodb+srv://Fabyoh:PeklMnKnGvA8Pcam@cluster0.f75tpn0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});



async function run() {
    try {
        await client.connect();

        const userCollection = client.db('Fabyoh').collection('users')

        app.post('/register', async (req, res) => {
            const UserData = req.body;
            try {
                const { email } = UserData;
                const existingUser = await userCollection.findOne({ email });
                if (existingUser) {
                    return res.status(409).json({ message: 'Email Already in use ' });
                }

                const hashedPassword = await bcrypt.hash(UserData.password, 10);
                UserData.password = hashedPassword;

                //  hashed password
                const result = await userCollection.insertOne(UserData);
                res.status(201).json({ message: "User created successfully." });
            } catch (error) {
                res.status(500).json({ message: 'Failed to create user' })
            }
        });

        app.post('/login', async (req, res) => {
            const { email, password } = req.body;
            try {
                if (!email || !password) {
                    return res.status(400).json({ message: 'Email and password are required' });
                }

                const user = await userCollection.findOne({ email });
                if (!user) {
                    return res.status(401).json({ message: "Invalid user or password" });
                }

                const matchPass = await bcrypt.compare(password, user.password);
                if (matchPass) {
                    const token = jwt.sign({ email: user.email }, "this-is-jwt-token", { expiresIn: '100' });
                    res.status(200).json({ message: 'Login successful', token });
                } else {
                    res.status(401).json({ message: 'Invalid user or password' });
                }
            } catch (error) {
                res.status(500).json({ message: 'Failed to login' });
            }
        });


        app.get('/userinfo', async (req, res) => {
            try {
                const { user } = req;
                const userInfo = await userCollection.findOne({ _id: user.id });
                if (!userInfo) {
                    return res.status(404).json({ message: 'User not found' })
                }
                res.json(userInfo)
            } catch (error) {
                res.status(500).json({ message: 'Internal Server Error' });
            }
        });


        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);
// Mongo DB default code..end


app.get('/', (req, res) => {
    res.send('FABYOH SERVER IS RUNNING...')
})
app.listen(port, () => {
    console.log(`FABYOH SERVER  RUNNING ON PORT:${port}`);
})

module.exports = app;