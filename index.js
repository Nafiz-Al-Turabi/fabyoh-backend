const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config()
const app = express();
const port = process.env.PORT || 5000;

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { default: Stripe } = require('stripe');
const paypal = require('paypal-rest-sdk');

const stripe = require("stripe")(process.env.STRIPE_KEY);
// paypal configuration
paypal.configure({
    'mode': 'sandbox',
    'client_id': process.env.PAYPAL_CLIENT_ID,
    'client_secret': process.env.PAYPAL_CLIENT_SECRET
});

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
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.f75tpn0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

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
        const wishListCollection = client.db('Fabyoh').collection('wishLists');
        const paymentCollection = client.db('Fabyoh').collection('payments');
        const productCollection = client.db('Fabyoh').collection('products');
        // ************************************ User Authentication***************************************
        // Middleware to check for admin or super admin
        function requireAdmin(req, res, next) {
            if (req.user.role !== 'admin' && req.user.role !== 'super admin') {
                return res.status(403).json({ message: 'Access denied. Admins only.' });
            }
            next();
        }

        // Middleware to check for super admin
        function requireSuperAdmin(req, res, next) {
            if (req.user.role !== 'super-admin') {
                return res.status(403).json({ message: 'Access denied. Super admin only.' });
            }
            next();
        }

        // Example: Only admins can access this route
        app.get('/admin-dashboard', verifyToken, requireAdmin, (req, res) => {
            res.send('Welcome to the admin dashboard');
        });

        // Example: Only super admins can access this route
        app.get('/super-admin-dashboard', verifyToken, requireSuperAdmin, (req, res) => {
            res.send('Welcome to the super admin dashboard');
        });

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
                UserData.role = 'user';
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
                    // Include the user's role in the token
                    const token = jwt.sign({ email: user.email, id: user._id, role: user.role }, jwtSecretKey, { expiresIn: '24h' });
                    res.status(200).json({ message: 'Login successful', token });
                } else {
                    res.status(401).json({ message: 'Invalid user or password' });
                }
            } catch (error) {
                res.status(500).json({ message: 'Failed to login' });
            }
        });

        app.get('/users', async (req, res) => {
            try {
                const userData = await userCollection.find().toArray();
                res.json(userData)
            } catch (error) {
                res.status(404).json({ message: 'User data not found' })
            }
        });

        app.put('/user/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            const updatedData = req.body;

            try {
                const user = await userCollection.findOne({ email: email });

                if (!user) {
                    return res.status(404).json({ message: 'User not found' });
                }

                const result = await userCollection.updateOne(
                    { email: email },
                    { $set: updatedData }
                );

                if (result.modifiedCount > 0) {
                    return res.status(200).json({ message: 'User updated successfully' });
                } else {
                    return res.status(400).json({ message: 'No changes made' });
                }
            } catch (error) {
                console.error('Error updating user:', error);
                return res.status(500).json({ message: 'Internal server error' });
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

        app.patch('/update-role/:id', verifyToken, requireSuperAdmin, async (req, res) => {
            const { id } = req.params;
            const { role } = req.body;

            if (!['user', 'admin', 'super admin'].includes(role)) {
                return res.status(400).json({ message: 'Invalid role' });
            }

            try {
                const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role } });
                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: 'User not found' });
                }
                res.status(200).json({ message: 'User role updated successfully' });
            } catch (error) {
                res.status(500).json({ message: 'Failed to update user role' });
            }
        });

        app.delete('/user/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            try {
                const deleteUser = await userCollection.deleteOne({ _id: new ObjectId(id) })
                if (deleteUser.deletedCount === 0) {
                    return res.status(404).json({ message: 'User not found' })
                }
                res.status(200).json({ message: 'User deleted successfully' });
            } catch (error) {
                res.send(500).json({ message: 'Faild to delete user', error })
            }
        })

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
            const id = req.params.id;
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
        // ************************************ Payment Api ***************************************
        app.post('/create-payment-intent', verifyToken, async (req, res) => {
            try {
                const { price } = req.body;
                const amount = parseInt(price * 100);
                // console.log(amount);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount,
                    currency: 'usd',
                    payment_method_types: ['card']
                });

                res.send({
                    clientSecret: paymentIntent.client_secret
                });
            } catch (error) {
                res.status(500).send({ error: error.message });
            }
        });

        app.post('/payment', verifyToken, async (req, res) => {
            const payment = req.body;
            try {
                const result = await paymentCollection.insertOne(payment);
                const query = {
                    email: payment.email,
                    _id: {
                        $in: payment.id.map(id => new ObjectId(id))
                    }
                };
                const deleteResult = await cartCollection.deleteMany(query);
                res.status(200).json({
                    message: "Order Placed Successfully and Cart Items Deleted",
                    paymentResult: result,
                    cartDeleteResult: deleteResult
                });
            } catch (error) {
                res.status(500).json({
                    message: 'Something went wrong while placing the order',
                    error
                });
            }
        });

        app.get('/orders', verifyToken, async (req, res) => {
            const email = req.user?.email;

            if (!email) {
                return res.status(400).send({ message: 'Invalid user email' });
            }

            try {
                const result = await paymentCollection.find({ email }).toArray();
                res.send(result);
            } catch (error) {
                console.error('Failed to get result', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });


        app.get('/adminOrders', verifyToken, async (req, res) => {
            try {
                const result = await paymentCollection.find().toArray();
                res.status(200).json(result)
            } catch (error) {
                res.status(500).json({ message: 'Admin Orders not found', error });
            }
        });

        app.patch('/adminOrders/:id', verifyToken, async (req, res) => {
            const { id } = req.params;
            const { newStatus } = req.body;

            try {
                const result = await paymentCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: newStatus } }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: 'Order not found' });
                } else if (result.modifiedCount === 0) {
                    return res.status(400).json({ message: 'Status unchanged' });
                }

                res.status(200).json({ message: 'Order status updated successfully' });
            } catch (error) {
                res.status(500).json({ message: 'Failed to update order status', error });
            }
        });

        // ################################# paypal ##########################################

        app.post('/paypal/create-payment', verifyToken, (req, res) => {
            const create_payment_json = {
                "intent": "sale",
                "payer": {
                    "payment_method": "paypal"
                },
                "redirect_urls": {
                    "return_url": "http://localhost:5000/success", // front-end success URL
                    "cancel_url": "http://localhost:5000/cancel"   // front-end cancel URL
                },
                "transactions": [{
                    "item_list": {
                        "items": [{
                            "name": "Item Name",
                            "sku": "item",
                            "price": req.body.amount,
                            "currency": "USD",
                            "quantity": 1
                        }]
                    },
                    "amount": {
                        "currency": "USD",
                        "total": req.body.amount
                    },
                    "description": "This is the payment description."
                }]
            };
            paypal.payment.create(create_payment_json, function (error, payment) {
                if (error) {
                    res.status(500).json({ error: error.message })
                } else {
                    const redirectUrl = payment.links.find(link => link.rel === 'approval_url').href;
                    res.json({ forwardLink: redirectUrl });
                }
            })
        });

        // Route to execute payment after approval
        app.post('/paypal/execute-payment', (req, res) => {
            const paymentId = req.body.paymentId;
            const payerId = { payer_id: req.body.payerId };

            paypal.payment.execute(paymentId, payerId, function (error, payment) {
                if (error) {
                    res.status(500).json({ error: error.message });
                } else {
                    res.json({ success: true, payment });
                }
            });
        });
        // ################################# paypal End ##########################################

        // ************************************ Payment end ***************************************
        // ************************************ Add Products ***************************************
        app.post('/addproduct', verifyToken, async (req, res) => {
            const formData = req.body;
            try {
                const addData = await productCollection.insertOne(formData);
                res.status(200).json({ message: 'Product Added Successfully' })
            } catch (error) {
                res.status(500).json({ message: 'Faild to add products' })
            }
        });

        app.get('/products', async (req, res) => {
            try {
                const productData = await productCollection.find().toArray();
                res.status(200).json(productData);
            } catch (error) {
                res.status(500).json({ message: "Products not found" });
            }
        });
        app.get('/products/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) }
                const details = await productCollection.findOne(query);
                res.send(details)
            } catch (error) {
                res.json({ message: 'Failed to find product details' })
            }
        });

        app.put('/products/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const updateProduct = req.body;

            try {
                const product = await productCollection.findOne({ _id: new ObjectId(id) });

                if (!product) {
                    return res.status(404).json({ message: 'Product not found' });
                }

                const result = await productCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateProduct }
                );


                res.status(200).json({
                    message: 'Product updated successfully',
                    result,
                });
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Error updating product', error });
            }
        });

        app.delete('/products/:id', verifyToken, async (req, res) => {
            const id = req.params.id
            try {
                const query = { _id: new ObjectId(id) };
                const delleteProduct = await productCollection.deleteOne(query);

                if (delleteProduct.deletedCount === 0) {
                    return res.status(404).json({ message: 'Product not found' });
                }
                res.status(200).json({ message: 'Product Deleted Succesfully' })
            } catch (error) {
                res.status(200).json({ message: 'Failed to  Delete product' })
            }
        });

        // ************************************ Add Products end ***************************************


        app.post('/wishlist', verifyToken, async (req, res) => {
            try {
                const { user } = req;
                const item = { ...req.body, email: user.email };
                const wishList = await wishListCollection.insertOne(item)
                res.status(200).json({ message: 'Wishlist added successfully.' });
            } catch (error) {
                res.status(500).json({ message: 'Failed to add wishlist' });
            }
        });

        app.get('/wishlists', verifyToken, async (req, res) => {
            const { email } = req.user;

            try {
                const wishlists = await wishListCollection.find({ email }).toArray();

                res.status(200).json(wishlists);
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Failed to get wishlist' });
            }
        });

        app.delete('/wishlist/:id', verifyToken, async (req, res) => {
            const id  = req.params.id; 
            console.log(id);
            try {
                const result = await wishListCollection.deleteOne({ _id: id });
                console.log(result);

                if (result.deletedCount === 1) {
                    res.status(200).json({ message: 'Wishlist item deleted successfully.' });
                } else {
                    res.status(404).json({ message: 'Wishlist item not found.' });
                }
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Failed to delete wishlist item' });
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