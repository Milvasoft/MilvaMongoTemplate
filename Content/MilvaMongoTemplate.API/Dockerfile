#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/sdk:5.0-alpine AS build
WORKDIR /app
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:xhttpportxx
EXPOSE xhttpportxx/tcp

COPY *.sln .

COPY ["MilvaMongoTemplate.Localization/MilvaMongoTemplate.Localization.csproj", "MilvaMongoTemplate.Localization/"]
COPY ["MilvaMongoTemplate.Entity/MilvaMongoTemplate.Entity.csproj", "MilvaMongoTemplate.Entity/"]
COPY ["MilvaMongoTemplate.Data/MilvaMongoTemplate.Data.csproj", "MilvaMongoTemplate.Data/"]
COPY ["MilvaMongoTemplate.API/MilvaMongoTemplate.API.csproj", "MilvaMongoTemplate.API/"]

RUN dotnet restore

COPY MilvaMongoTemplate.Localization/. MilvaMongoTemplate.Localization/
COPY MilvaMongoTemplate.Entity/. MilvaMongoTemplate.Entity/
COPY MilvaMongoTemplate.Data/. MilvaMongoTemplate.Data/
COPY MilvaMongoTemplate.API/. MilvaMongoTemplate.API/

WORKDIR "/app/MilvaMongoTemplate.API"
RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/aspnet:5.0-buster-slim AS runtime
WORKDIR /app

COPY --from=build /app/MilvaMongoTemplate.API/out ./


ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8

ENTRYPOINT ["dotnet", "MilvaMongoTemplate.API.dll"]