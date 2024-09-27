
const client = require("../uri/client");

const getWhshList = async (req, res) => {
    const { email } = req.user;

    try {
        await client.connect(); 
        const wishListCollection = client.db('Fabyoh').collection('wishLists');
        const wishlists = await wishListCollection.find({ email }).toArray();
        return res.status(200).json(wishlists);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to get wishlist' });
    }
};

module.exports = { getWhshList };
