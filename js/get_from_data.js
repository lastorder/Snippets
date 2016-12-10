

var form2Json = formId=>{
  var result = {};
  $("#"+formId).serializeArray().forEach(data=>{
    result[data.name] = data.value;
  });
  return JSON.stringify(result);
}

json = form2Json("test-form");