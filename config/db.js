const mongoose = require("mongoose")

module.exports = (connect) = async(req, res) => {
    try {
        const response = await mongoose.connect('mongodb://0.0.0.0:27017/auth')
        console.log("Database Connected Successfully.");
    } catch (error) {
        console.log("Mongoose Connection Error: ", error);
    }
}