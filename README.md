<h2 align="center">Web API Template with MongoDB for .Net 6</h2>
  
 <div align="center"> 
  
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Milvasoft/Milvasoft/blob/master/LICENSE)  [![NuGet](https://img.shields.io/nuget/v/Milvasoft.Templates.Web.Ef)](https://www.nuget.org/packages/Milvasoft.Helpers/)   [![NuGet](https://img.shields.io/nuget/dt/Milvasoft.Templates.Web.Mongo)](https://www.nuget.org/packages/Milvasoft.Templates.Web.Mongo) 

</div>

<h3 align="center">Create ready made project with <a href="https://github.com/Milvasoft/Milvasoft" rel="nofollow" target="_blank" >Milvasoft.Helpers</a></h3>

***

# How can I create project with CLI?

<ol> 

<li>Install the latest <a href="https://dot.net" rel="nofollow" target="_blank">.NET Core SDK</a> and <a href="https://visualstudio.microsoft.com/tr/thank-you-downloading-visual-studio/?sku=Community&rel=16" rel="nofollow" target="_blank" >Visual Studio 2019</a></li>
<li>Run <code>dotnet new --install Milvasoft.Templates.Web.Mongo</code> to install the project template.</li>
<li>Run <code>dotnet new milvawebmongo --help</code> to see how to select the feature of the project.</li>
<li>Run <code>dotnet new milvawebmongo --name</code> "MyProject" along with any other custom options to create a project from the template.</li>

</ol>

# How can I create project with VS?

<li>Install the latest <a href="https://dot.net" rel="nofollow" target="_blank">.NET Core SDK</a> and <a href="https://visualstudio.microsoft.com/tr/thank-you-downloading-visual-studio/?sku=Community&rel=16" rel="nofollow" target="_blank" >Visual Studio 2019</a></li>
<li>Run <code>dotnet new --install Milvasoft.Templates.Web.Mongo</code> to install the project template.</li>
<li>Close all Visual Studio instances.</li>
<li>Open Visual Studio and click "Create New Project". Search for Milva, select template and click next.</li>
<li>After that, steps are same as create project.</li>
<br></br>

> <b>Note :</b> If you select "Place solution and project in same directory" box, you need add project to solution with "Add New Existing Project")

![Capture](https://user-images.githubusercontent.com/32344242/135268651-227dc8ed-24a1-4e02-bb53-e1af9edd0c36.PNG)

<br>

># Project Structure

### **Layers;**

- **Localization :** Contains localization key-value pairs.
- **Entity :** Contains database related models. Under normal circumstances, the entity layer is not created as a separate project. It is a folder within the data layer. We prefer this structure, as creating the Entity as a layer facilitates us in establishing business logics using with the Assembly class.
- **Data :** Database connections are made here.
- **API :** This is the executable part of the project. All the business logic happens here. Endpoints and project-specific business logics written for the client are written here. Project configurations, files that will/will not be served to the Client are here.

<br>

># File Structure

<br>

## **Localization Layer**

There are Resources folder for hold localization key-value pairs language by language.

- Each file name has the language code at the end. According to these language codes, we do it in order to use the Localization structure built in .Net Core. Resx file without language extension code is the default language file. We did this to get rid of magic strings using auto generated code.

- SharedResource.cs is a dummy class for access localization key-value pairs.

<br>

## **Entity Layer**

- Classes in Collections folder in this layer represents database collections,
- Classes in EmbeddedDocuments folder in this layer represents embedded documents,
- Utils folder contains helper classes to this models.

<br>

## **Data Layer**

- Database seed made with DataSeed.

<br>

## **API Layer**

Under normal circumstances, the Services folder and a few more folders are created in Core named layer. We see the layer we call API as the Business layer in other companies projects. Since project dependencies do not change, we use it this way because managing them as folders in the same layer increases efficiency rather than creating separate layers for them.

### **Folders;**
- **wwwroot :** Contains public static files.
- **AppStartup :** Contains application startup configuration.
- **Controllers :** Contains endpoints which public to client. No business logic here. All controllers are similar.
- **DTOS :** Contains Data Transfer Objects open to the client. It provides abstraction of entity models, that is, database structure, from the client.
- **Middlewares :** It contains custom middlewares running on the project.
- **Migrations :** It includes automatically generated migrations and Data Seed components.
- **Services :** The business logic of the whole project is here. This is the most complicated place. Endpoints call these service methods, and the service methods provide the necessary business logic and perform the related operation(data update in database etc.). 
- **StaticFiles :** Contains private static files. It can be html files to be sent as mail.


### **Files;**
- **FodyWeavers.xml :** It is the configuration file of the Fody library that we use to avoid writing ConfigureAwait(false) at the end of asynchronous methods in the whole project.
- **ProjectName.API.xml :** It is an xml file that is automatically created as a result of the summary we have written. We create Open Api documentation from this file with the Swashbuckle library. If you change a summary, rebuild project for recreate this file.

<br>

## **Project Dependencies**

<br>

![ApiLayerFileStructure](https://user-images.githubusercontent.com/32344242/142745035-cede3747-ab37-4bf4-b0e2-08c7e50048e2.png)

<br>

### **Projects Build Order**

- Entity
- Localization
- Data
- API
