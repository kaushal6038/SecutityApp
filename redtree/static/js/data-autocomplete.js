
var article_details;
var hosts_detail;

$(document).ready(function(){
  
  $.ajax({ 
    url: "/vulnerabilites-detail",
    dataType: 'json',
    success: function(response){
      article_details = response;
    },
    async: false
  });
  
  $( "#id_title" ).autocomplete({
    minLength: 2,
    source: article_details,
    focus: function( event, ui ) {
      $( "#id_title" ).val( ui.item.label );
      return false;
    },
    select: function( event, ui ) {
      $( "#id_title" ).val( ui.item.label );
      $( "#id_risk" ).val( ui.item.risk );
      $( "#virtue_id" ).val( ui.item.virtue_id );
      $( "#id_remediation" ).val( ui.item.remediation );
      $( "#id_description" ).val( ui.item.description );
      return false;
    }
  });

  $.ajax({ 
    url: "/autocomplete-hosts",
    dataType: 'json',
    success: function(response){
      hosts_detail = response;
    },
    async: false
  });

 $( "#host" ).autocomplete({
      source: hosts_detail,
      minLength: 2,
      
    });
});