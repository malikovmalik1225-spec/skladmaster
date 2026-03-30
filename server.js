require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

mongoose
  .connect("mongodb://127.0.0.1:27017/skladmaster")
  .then(() => console.log("MongoDB ulandi"))
  .catch((err) => console.log("MongoDB xato:", err));

const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    storeName: { type: String, default: "" }
  },
  { timestamps: true }
);

const productSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    name: { type: String, required: true },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    unit: { type: String, required: true },
    size: { type: String, default: "" }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Token yo'q" });
    }

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Noto'g'ri token" });
  }
}

app.get("/health", (req, res) => {
  res.json({ ok: true, message: "Sklad Master ishlayapti" });
});

app.post("/register", async (req, res) => {
  try {
    const { username, password, storeName } = req.body;

    if (!username?.trim() || !password?.trim()) {
      return res.status(400).json({ message: "Login va parol kerak" });
    }

    const existingUser = await User.findOne({ username: username.trim() });

    if (existingUser) {
      return res.status(400).json({ message: "Bu login band" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username: username.trim(),
      password: hashedPassword,
      storeName: storeName?.trim() || ""
    });

    await newUser.save();

    res.json({ message: "User yaratildi" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server xatosi" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username?.trim() || !password?.trim()) {
      return res.status(400).json({ message: "Login va parol kiriting" });
    }

    const user = await User.findOne({ username: username.trim() });

    if (!user) {
      return res.status(400).json({ message: "Login topilmadi" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Parol noto'g'ri" });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        username: user.username,
        storeName: user.storeName || ""
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login muvaffaqiyatli",
      token,
      username: user.username,
      storeName: user.storeName || ""
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server xatosi" });
  }
});

app.get("/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Xato" });
  }
});

app.get("/products", auth, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: "Xato" });
  }
});

app.post("/products", auth, async (req, res) => {
  try {
    const { name, quantity, price, category, unit, size } = req.body;

    if (!name?.trim() || quantity == null || price == null || !category?.trim() || !unit?.trim()) {
      return res.status(400).json({ message: "Maydonlarni to'ldiring" });
    }

    const newProduct = new Product({
      userId: req.user.userId,
      name: name.trim(),
      quantity: Number(quantity),
      price: Number(price),
      category: category.trim(),
      unit: unit.trim(),
      size: size ? size.trim() : ""
    });

    await newProduct.save();

    res.json({ message: "Mahsulot qo'shildi" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Xato" });
  }
});

app.delete("/products/:id", auth, async (req, res) => {
  try {
    const deleted = await Product.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!deleted) {
      return res.status(404).json({ message: "Mahsulot topilmadi" });
    }

    res.json({ message: "Mahsulot o'chirildi" });
  } catch (error) {
    res.status(500).json({ message: "Xato" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server ishga tushdi -> ${PORT}`);
});
app.get("/", (req, res) => {
  res.send("Ombor API ISHLAYAPTI");
});