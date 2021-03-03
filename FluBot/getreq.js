// frida script for sample 30937927e8891f8c0fd2c7b6be5fbc5a05011c34a7375e91aad384b82b9e6a67
Java.perform(function(){
    let Color = {
                Reset: '\x1b[39;49;00m',
                Black: '\x1b[30;01m', Blue: '\x1b[34;01m', Cyan: '\x1b[36;01m', Gray: '\x1b[37;11m',
                Green: '\x1b[32;01m', Purple: '\x1b[35;01m', Red: '\x1b[31;01m', Yellow: '\x1b[33;01m',
                Light: {
                                Black: '\x1b[30;11m', Blue: '\x1b[34;11m', Cyan: '\x1b[36;11m', Gray: '\x1b[37;01m',
                                Green: '\x1b[32;11m', Purple: '\x1b[35;11m', Red: '\x1b[31;11m', Yellow: '\x1b[33;11m'
                            }
            };
    let dalvik = Java.use("dalvik.system.DexFile")
    dalvik.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function(a,b,c){
        console.log("[+] loadDex Catched -> " + a)
        return dalvik.loadDex(a,b,c)
    }
    let dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    dexclassLoader.$init.implementation = function(a,b,c,d){
        console.log(Color.Green+"\n[+] DexClassLoader $init called !\n Hooking classes from file ",a,Color.Reset)
        this.$init(a,b,c,d)
        try{
            hookloadedfunctions(this)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
        }

    }
    function hookloadedfunctions(dexclassloader){
            Java.classFactory.loader = dexclassloader 
            let target_class = "com.example.myapplicationtest.PanelReq"
            try{
                let res = dexclassloader.findClass(target_class);
            }
            catch(e){
                console.log(Color.Red+e,Color.Reset)
                return
            }
            //Class found, you can hook with Java.use since current loader is dexclassloader
            let class_ref = Java.use(target_class)
            console.log(Color.Green+"[+] Hooking : ",class_ref,Color.Reset)
            class_ref.Send.overload('java.lang.String').implementation = function(a){
                let retval = class_ref.Send(a)
                console.log(Color.Yellow+"Sending : ",a,Color.Reset)
                console.log(Color.Green+"Received :",retval,Color.Reset)
                return retval
            }
    }

    

})
