const mongoose = require("mongoose");
mongoose.set("strictQuery", false);
require("dotenv").config();
const url = process.env.MONGODB_URI;
console.log("connecting to", url);

mongoose
    .connect(url)
    .then((result) => {
        console.log("connected to MongoDB");
    })
    .catch((error) => {
        console.log("error connecting to MongoDB:", error.message);
    });

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true, // esto asegura la unicidad de username
    },
    name: String,
    passwordHash: String,
    email: String,
});

userSchema.set("toJSON", {
    transform: (document, returnedObject) => {
        returnedObject.id = returnedObject._id.toString();
        delete returnedObject._id;
        delete returnedObject.__v;
        // el passwordHash no debe mostrarse
        delete returnedObject.passwordHash;
    },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
