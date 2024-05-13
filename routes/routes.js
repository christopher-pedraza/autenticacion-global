const router = require("express").Router();
const user = require("../controllers/user");
const productos = require("../controllers/productos");

router.use("/user", user);
router.use("/productos", productos);

module.exports = router;
