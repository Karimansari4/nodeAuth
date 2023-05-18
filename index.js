const express = require('express')
const app = express()
const cors = require('cors')
const db = require('./config/db')
const userRouter = require('./route/user')
const dotenv = require('dotenv')
dotenv.config()
const port = process.env.PORT || 4000


db()

app.use(cors())
app.use(express.json())

app.get('/', (req, res) => res.send('Hello World!'))

app.use('/users', userRouter)

app.listen(port, () => console.log(`Example app listening on port ${port}!`))