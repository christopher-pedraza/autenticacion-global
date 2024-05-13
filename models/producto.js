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

const productSchema = new mongoose.Schema({
    content: {
        producto: String,
        precio: Number,
        imagen: String,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    },
});

productSchema.set("toJSON", {
    transform: (document, returnedObject) => {
        returnedObject.id = returnedObject._id.toString();
        delete returnedObject._id;
        delete returnedObject.__v;
    },
});

module.exports = mongoose.model("Producto", productSchema);
