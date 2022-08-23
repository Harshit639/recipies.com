var express = require("express")
var bodyParser = require("body-parser")
var mongoose = require("mongoose")
const User = require('./model/user')
const jwt = require('jsonwebtoken')
const JWT_SECRET = process.env.JWT_SECRET
const url= process.env.MONGO_URL
const app = express()
const bcrypt = require('bcryptjs')
require('dotenv').config()
app.use(bodyParser.json())
app.use(express.static('public'))
app.use(bodyParser.urlencoded({
    extended:true
}))

mongoose.connect(process.env.MONGO_URL,{
    useNewUrlParser: true,
    useUnifiedTopology: true
});

var db = mongoose.connection;

db.on('error',()=>console.log("Error in Connecting to Database"));
db.once('open',()=>console.log("Connected to Database"))

app.post("/sign_up", async (req,res)=>{
    var username = req.body.name;
    var email = req.body.email;
  
    var plainTextPassword = req.body.password;
    if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
		throw error
	}

    // var data = {
    //     "name": name,
    //     "email" : email,
    //     "password" : password
    // }

    // db.collection('users').insertOne(data,(err,collection)=>{
    //     if(err){
    //         throw err;
    //     }
    //     console.log("Record Inserted Successfully");
    // });

    return res.redirect('login.html')
})

app.post('/login', async (req, res) => {
    var username = req.body.name;
    var email = req.body.email;
  
    var password = req.body.password;
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			process.env.JWT_SECRET
		)

		return res.redirect('recipies.html')
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})


app.get("/",(req,res)=>{
    res.set({
        "Allow-access-Allow-Origin": '*'
    })
    return res.redirect('index.html');
}).listen(process.env.PORT);


console.log("Listening on PORT 3000");