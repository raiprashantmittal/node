userSchema.methods.generatePasswordResetHash = function(){
    const resetHash = crypto.createHash('').update(this.hash).digest('')
    return resetHash;
}