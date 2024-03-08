require('dotenv').config()

const mongoose=require('mongoose')
const express=require('express')
const cors=require('cors')

const mongo_db_url=process.env.mongo_db

const userRoute=require('./routes/userRoute')

const app=express()

app.use(express.json())
app.use(cors())

app.use('/',userRoute)


//Database connection 
mongoose.connect(mongo_db_url)
    .then(response=>console.log('MongoDB connected successfully'))
    .catch(error=>console.log(error))

//Running Server on Port 3000
app.listen(4000,()=>{
       console.log('server running')
})