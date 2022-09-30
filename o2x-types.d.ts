declare module 'object-to-xml'{
  function objectToXML(obj : object, namespace? : String, depth? : number) : String;

  export = objectToXML;
}