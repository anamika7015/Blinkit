import mongoose from "mongoose";

const subCategorySchema = new mongoose.Schema({
    name :{
        type : String,
        default : ""
    },
    image :{
        type : String,
        default : ""
    },
    category :[
        {
            type : mongoose.Schema.ObjectId,
            ref : "subCategory"
        }
    ]
},{
    timestamps : true
})

const SubCategoryModel = mongoose.Model('subCategory', subCategorySchema)

export default SubCategoryModel