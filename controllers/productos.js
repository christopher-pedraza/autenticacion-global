const jwt = require("jsonwebtoken");
const productosRouter = require("express").Router();
const productoModel = require("../models/producto");
const userModel = require("../models/user");

const getTokenFrom = (request) => {
    const authorization = request.get("authorization");
    if (authorization && authorization.startsWith("Bearer ")) {
        return authorization.replace("Bearer ", "");
    }
    return null;
};

productosRouter.get("/", (request, response) => {
    productoModel.find({}).then((productList) => {
        response.json(productList);
    });
});

productosRouter.get("/:id", (request, response) => {
    productoModel
        .findById(request.params.id)
        .then((producto) => {
            if (producto) {
                response.json(producto);
            } else {
                response.status(404).end();
            }
        })
        .catch((error) => {
            console.log(error);
            response.status(400).send({ error: "malformatted id" });
        });
});

productosRouter.delete("/:id", (request, response) => {
    productoModel
        .findByIdAndDelete(request.params.id)
        .then((result) => {
            response.status(204).end();
        })
        .catch((error) => {
            console.log(error);
        });
});

productosRouter.post("/", (request, response) => {
    const body = request.body;
    const decodedToken = jwt.verify(getTokenFrom(request), process.env.SECRET);

    if (!decodedToken.id) {
        return response.status(401).json({ error: "token invalid" });
    }
    const user = userModel.findById(decodedToken.id);

    if (body.content.producto === undefined) {
        return response.status(400).json({ error: "content missing" });
    }

    const product = new productoModel({
        content: {
            producto: body.content.producto,
            precio: body.content.precio || 0,
            imagen:
                body.content.imagen ||
                "https://dummyimage.com/300x200/000/292929",
        },
    });

    product.save().then((savedProduct) => {
        response.json(savedProduct);
    });
});

productosRouter.put("/:id", (request, response, next) => {
    const body = request.body;

    const producto = {
        content: {
            producto: body.content.producto,
            precio: body.content.precio,
            imagen: body.content.imagen,
        },
    };

    productoModel
        .findByIdAndUpdate(request.params.id, producto, { new: true })
        .then((updatedProduct) => {
            response.json(updatedProduct);
        })
        .catch((error) => next(error));
});

module.exports = productosRouter;
