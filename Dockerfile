FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY WebAPI_TongNhatBaoAn.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 10000
ENTRYPOINT ["dotnet", "WebAPI_TongNhatBaoAn.dll"]
