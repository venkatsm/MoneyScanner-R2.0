

/*=============================================================
    Authour URI: www.binarytheme.com
    License: Commons Attribution 3.0

    http://creativecommons.org/licenses/by/3.0/

    100% To use For Personal And Commercial Use.
    IN EXCHANGE JUST GIVE US CREDITS AND TELL YOUR FRIENDS ABOUT US
   
    ========================================================  */
function isNumber(evt) {
    evt = (evt) ? evt : window.event;
    var charCode = (evt.which) ? evt.which : evt.keyCode;
    if (charCode > 31 && (charCode < 48 || charCode > 57)) {
        return false;
    }
    return true;
}
function isDecimal(evt) {
    evt = (evt) ? evt : window.event;
    var charCode = (evt.which) ? evt.which : evt.keyCode;
    if (charCode > 31 && (charCode < 46 || charCode > 46) && (charCode < 48 || charCode > 57)) {
        return false;
    }
    return true;
}

(function ($) {
    "use strict";
    var mainApp = {

        main_fun: function () {
            
            $.get("../partials/_header.html", function (data) {
                $('#header').html(data);
                $('#' + $('#currentpage').val()).addClass('active');
                $('#loginc').click(function () {
                    $('.navbar-nav li').removeClass('active');
                    $('#signinlink').addClass('active');
                });
                $('#Registerc').click(function () {
                    $('.navbar-nav li').removeClass('active');
                    $('#signuplink').addClass('active');
                });
                $('#signin').on('hidden.bs.modal', function (e) {
                    $('#signinlink').removeClass('active');
                    $('#' + $('#currentpage').val()).addClass('active');
                });
                $('#signup').on('hidden.bs.modal', function (e) {
                    $('#signuplink').removeClass('active');
                    $('#' + $('#currentpage').val()).addClass('active');
                });
            });
            $.get("../partials/_footer.html", function (data) {
                $('#footer').html(data);
            });

            //ADD REMOVE PADDING CLASS ON SCROLL
         
            //SLIDESHOW SCRIPT
            $('.carousel').carousel({
                interval: 5000 //TIME IN MILLI SECONDS
            })
            // PRETTYPHOTO FUNCTION 
  

            /*====================================
               WRITE YOUR SCRIPTS BELOW 
           ======================================*/
           // $('.flexslider').flexslider({
           //     animation: "slide",
           //    animationLoop: true,
           //   itemWidth: 210,
           //    itemMargin: 5,
           //     minItems: 2,
           //     maxItems: 5
           // });
            $('#signup-model').click(function () {
                $('#signin').modal('hide').on('hidden.bs.modal', function (e) {
                $('#signup').modal('show');
                $(this).off('hidden.bs.modal'); // Remove the 'on' event binding
            });
            });
            $('#signin-model').click(function(){
                $('#signup').modal('hide').on('hidden.bs.modal', function (e) {
                $('#signin').modal('show');
                $(this).off('hidden.bs.modal'); // Remove the 'on' event binding
            });
            });
            //$('#get-started').click(function(){
              //      window.open('compare.html', "_self");
            //});
            
	
	 //   $.ajax({
	//	  xhrFields: {
      	//		  withCredentials: true
	//	  },
	//	  type:"GET",
	//	  headers: { 'Access-Control-Allow-Origin': '*' },
	//	  crossDomain: true,
	//	  url: "https://www.google.com/finance/converter?a=1&from=USD&to=INR"
	//		
	//	})
	//	  .done(function( data ) {
	//	    alert(data);
	  //  });


        },

        initialization: function () {
            mainApp.main_fun();

        }

    }
    // Initializing ///

    $(document).ready(function () {
        mainApp.main_fun();
    });

}(jQuery));



