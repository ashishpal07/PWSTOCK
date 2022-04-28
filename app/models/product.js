const mongoose = require('mongoose')
const Schema = mongoose.Schema

const productSchema = new Schema({
    name: { type: String, required: true },
    image: { type: String, required: true },
    price: { type: Number, required: true },
    size: { type: String, required: true },
    flag: { type: Number, default: 0 }
})

module.exports = mongoose.model('Product', productSchema)