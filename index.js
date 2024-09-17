const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config()
const app = express();
const port = process.env.PORT || 5000;

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// middleware
app.use(cors());
app.use(express.json());

// Middleware to authenticate the token
const jwtSecretKey = process.env.SECRET_KEY;
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token part
    if (!token) {
        return res.status(401).json('Access denied');
    }

    try {
        const decoded = jwt.verify(token, jwtSecretKey);
        req.user = decoded; // Attach decoded user to request object
        next();
    } catch (error) {
        console.error('Error verifying token:', error);
        return res.status(403).json({ message: 'Invalid token' });
    }
}


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

        const userCollection = client.db('Fabyoh').collection('users');
        const cartCollection = client.db('Fabyoh').collection('carts');
        // ************************************ User Authentication***************************************
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
                    const token = jwt.sign({ email: user.email, id: user._id }, jwtSecretKey, { expiresIn: '1h' });
                    res.status(200).json({ message: 'Login successful', token });
                } else {
                    res.status(401).json({ message: 'Invalid user or password' });
                }
            } catch (error) {
                res.status(500).json({ message: 'Failed to login' });
            }
        });

        app.get('/userinfo', verifyToken, async (req, res) => {
            try {
                const { user } = req;
                const userInfo = await userCollection.findOne({ _id: new ObjectId(user.id) });
                if (!userInfo) {
                    return res.status(404).json({ message: 'User not found' });
                }
                res.json(userInfo);
            } catch (error) {
                console.error('Error in /userinfo:', error);
                res.status(500).json({ message: 'Internal Server Error' });
            }
        });
        // ************************************ User Authentication End***************************************

        // ************************************ User Cart ***************************************


        app.post('/cart', verifyToken, async (req, res) => {
            try {
                const { user } = req;
                const item = { ...req.body, email: user.email };
                const cart = await cartCollection.insertOne(item);
                res.status(200).json({ message: 'Cart added successfully.' });
            } catch (error) {
                res.status(404).json({ message: 'Failed to add cart.', error });
            }
        });



        app.get('/carts', verifyToken, async (req, res) => {
            const { user } = req;
            try {
                const userCart = await cartCollection.find({ email: user.email }).toArray();
                if (userCart.length > 0) {
                    res.status(200).json(userCart);
                } else {
                    res.status(404).json({ message: 'Cart not found' });
                }
            } catch (error) {
                console.error('Error fetching cart:', error);
                res.status(500).json({ message: 'Failed to fetch cart', error });
            }
        });

        app.delete('/carts/:id', verifyToken, async (req, res) => {
            const id = req.params.id; // Get the ID from route parameters
        
            try {
                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ message: 'Invalid ID format' });
                }
        
                const deleteResult = await cartCollection.deleteOne({ _id: new ObjectId(id) });
        
                if (deleteResult.deletedCount === 0) {
                    return res.status(404).json({ message: 'Cart item not found' });
                }
        
                res.status(200).json({ message: 'Cart item deleted successfully' });
            } catch (error) {
                res.status(500).json({ message: 'Error deleting cart item', error: error.message });
            }
        });

        app.patch('/cart/:id', verifyToken, async (req, res) => {
            const id = req.params.id; // Get the ID from route parameters
            const { user } = req;
            const updateData = req.body;
        
            try {
                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ message: 'Invalid ID format' });
                }
        
                // Validate update data if necessary
                if (updateData.quantity && updateData.quantity <= 0) {
                    return res.status(400).json({ message: 'Quantity must be greater than 0' });
                }
        
                const result = await cartCollection.updateOne(
                    { _id: new ObjectId(id), email: user.email },
                    { $set: updateData }
                );
        
                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: 'Cart item not found or not owned by the user' });
                }
        
                res.status(200).json({ message: 'Cart item updated successfully' });
            } catch (error) {
                console.error('Error updating cart item:', error);
                res.status(500).json({ message: 'Failed to update cart item', error: error.message });
            }
        });
        
        
        

        // ************************************ User Cart end ***************************************





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